"""IP scanner engine for batch IP list connectivity diagnostics.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
import threading
import time
from typing import Callable, List, Optional

from models.results import ApplicationSettings, ScanResult, ScanStatus, ScanTarget, TCPResult, TLSResult
from network.tcp import TCPTester
from network.tls import TLSTester
from utils.validation import is_valid_ip


class IPScanner:
    """Tests lists of IPv4 and IPv6 endpoints for TCP and TLS reachability."""

    def __init__(self, settings: Optional[ApplicationSettings] = None) -> None:
        self.settings = settings or ApplicationSettings()
        self.tcp_tester = TCPTester(timeout=self.settings.tcp_timeout)
        self.tls_tester = TLSTester(timeout=self.settings.tls_timeout)
        self._is_cancelled = threading.Event()
        self._lock = threading.Lock()

    def cancel(self) -> None:
        self._is_cancelled.set()

    def test_single_ip(
        self,
        ip: str,
        port: int = 443,
        test_tls: bool = True,
        sni: Optional[str] = None,
    ) -> ScanResult:
        """Probe reachability for a single IP address."""
        clean_ip = ip.strip()
        target = ScanTarget(
            hostname=clean_ip,
            ip=clean_ip,
            port=port,
            sni=sni or clean_ip,
        )

        res = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
        )

        if not is_valid_ip(clean_ip):
            res.status = ScanStatus.FAILED
            res.notes = "Invalid IP address format"
            res.tcp.error = "Malformed IP"
            return res

        # 1. Test TCP Reachability
        tcp_res = self.tcp_tester.test_connection(clean_ip, port)
        res.tcp = tcp_res

        if not tcp_res.connected:
            res.status = ScanStatus.FAILED
            res.total_latency_ms = tcp_res.latency_ms
            res.notes = "Unreachable from current network"
            return res

        # 2. Test TLS if enabled or on port 443
        if test_tls:
            tls_res = self.tls_tester.test_tls(clean_ip, port, sni=sni or clean_ip)
            res.tls = tls_res
            res.total_latency_ms = tcp_res.latency_ms + (tls_res.latency_ms if tls_res.handshake_success else 0.0)
            if tls_res.handshake_success:
                res.status = ScanStatus.SUCCESS
                res.notes = "Reachable from current network (TLS Handshake OK)"
            else:
                res.status = ScanStatus.PARTIAL
                res.notes = f"Reachable from current network (TCP OK, TLS Failed: {tls_res.error or 'Refused'})"
        else:
            res.total_latency_ms = tcp_res.latency_ms
            res.status = ScanStatus.SUCCESS
            res.notes = "Reachable from current network (TCP Port Open)"

        return res

    def scan_ips(
        self,
        ip_list: List[str],
        port: int = 443,
        test_tls: bool = True,
        sni: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan a batch of IPs concurrently."""
        self._is_cancelled.clear()
        results: List[ScanResult] = []
        valid_ips = [ip.strip() for ip in ip_list if ip.strip()]
        total = len(valid_ips)
        tested = 0

        max_workers = min(self.settings.max_concurrency, max(1, total))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(self.test_single_ip, ip, port, test_tls, sni): ip
                for ip in valid_ips
            }

            for future in concurrent.futures.as_completed(future_to_ip):
                if self._is_cancelled.is_set():
                    break
                ip = future_to_ip[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = ScanResult(
                        target=ScanTarget(hostname=ip, ip=ip, port=port),
                        status=ScanStatus.FAILED,
                        notes=f"Internal IP scanner error: {str(e)}",
                    )

                with self._lock:
                    results.append(res)
                    tested += 1

                if result_callback:
                    result_callback(res)

                if progress_callback:
                    progress_callback(tested, total, f"Tested {ip}:{port}")

        return results
