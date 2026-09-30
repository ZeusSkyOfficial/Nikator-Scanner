"""SNI Compatibility testing engine for Nikator Scanner.
Researches TLS behavior, SNI negotiation, and certificate matching/mismatching
against specified hostnames, IP endpoints, or public datasets.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
from pathlib import Path
import threading
from typing import Callable, List, Optional

from models.results import (
    ApplicationSettings,
    CertificateInfo,
    DNSResult,
    HTTPResult,
    ScanResult,
    ScanStatus,
    ScanTarget,
    TCPResult,
    TLSResult,
)
from network.http_client import HTTPTester
from network.resolver import DNSResolver
from network.tcp import TCPTester
from network.tls import TLSTester


class CompatibilityScanner:
    """Evaluates SNI compatibility and TLS handshake response behaviors."""

    def __init__(self, settings: Optional[ApplicationSettings] = None) -> None:
        self.settings = settings or ApplicationSettings()
        self.dns_resolver = DNSResolver(timeout=self.settings.dns_timeout)
        self.tcp_tester = TCPTester(timeout=self.settings.tcp_timeout)
        self.tls_tester = TLSTester(timeout=self.settings.tls_timeout)
        self.http_tester = HTTPTester(timeout=self.settings.http_timeout)
        self._is_cancelled = threading.Event()
        self._lock = threading.Lock()

    def cancel(self) -> None:
        self._is_cancelled.set()

    def get_public_sni_candidates(self, limit: int = 50) -> List[str]:
        """Load public candidate hostnames from built-in research dataset."""
        candidates: List[str] = []
        path = Path(__file__).resolve().parent.parent / "data" / "datasets" / "sni_candidates.txt"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    item = line.strip().lower()
                    if item and not item.startswith("#") and item not in candidates:
                        candidates.append(item)
                        if len(candidates) >= limit:
                            break
        return candidates

    def test_sni_endpoint(
        self,
        target_ip_or_host: str,
        sni_candidate: str,
        port: int = 443,
    ) -> ScanResult:
        """Test how a specific IP or Host behaves when presented with a custom SNI."""
        target = ScanTarget(
            hostname=target_ip_or_host,
            port=port,
            sni=sni_candidate,
            protocol="https",
        )

        res = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
        )

        # 1. DNS check if target_ip_or_host is a domain
        primary_ip = target_ip_or_host
        dns_res = self.dns_resolver.resolve(target_ip_or_host)
        res.dns = dns_res
        if dns_res.resolved and dns_res.primary_ip:
            primary_ip = dns_res.primary_ip
            target.ip = primary_ip

        # 2. TCP Handshake
        tcp_res = self.tcp_tester.test_connection(primary_ip, port)
        res.tcp = tcp_res

        if not tcp_res.connected:
            res.status = ScanStatus.FAILED
            res.total_latency_ms = tcp_res.latency_ms
            res.notes = f"TCP connection failed to {primary_ip}:{port}"
            return res

        # 3. TLS Handshake with custom SNI
        tls_res = self.tls_tester.test_tls(primary_ip, port, sni=sni_candidate)
        res.tls = tls_res

        if not tls_res.handshake_success:
            res.status = ScanStatus.FAILED
            res.total_latency_ms = tcp_res.latency_ms + tls_res.latency_ms
            res.notes = f"SNI Rejection / TLS Handshake Failure: {tls_res.error or 'Unknown'}"
            return res

        # 4. HTTP probe over negotiated TLS
        http_res = self.http_tester.probe(
            host_or_ip=primary_ip,
            port=port,
            use_tls=True,
            sni=sni_candidate,
        )
        res.http = http_res

        total_lat = tcp_res.latency_ms + tls_res.latency_ms + (http_res.latency_ms if http_res.reachable else 0.0)
        res.total_latency_ms = total_lat

        # Classify Compatibility Behavior
        if tls_res.certificate_matches_sni:
            res.status = ScanStatus.SUCCESS
            res.notes = "Certificate Match: Server certificate directly validates requested SNI"
        else:
            res.status = ScanStatus.PARTIAL
            res.notes = (
                f"Certificate Mismatch: Handshake succeeded, but certificate belongs to "
                f"'{tls_res.certificate.subject or 'Unknown'}'"
            )

        return res

    def scan_compatibility(
        self,
        target_ip_or_host: str,
        sni_list: List[str],
        port: int = 443,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Perform concurrent SNI compatibility research across candidate list."""
        self._is_cancelled.clear()
        results: List[ScanResult] = []
        total = len(sni_list)
        tested = 0

        max_workers = min(self.settings.max_concurrency, max(1, total))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sni = {
                executor.submit(self.test_sni_endpoint, target_ip_or_host, sni, port): sni
                for sni in sni_list
            }

            for future in concurrent.futures.as_completed(future_to_sni):
                if self._is_cancelled.is_set():
                    break
                sni = future_to_sni[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = ScanResult(
                        target=ScanTarget(hostname=target_ip_or_host, sni=sni, port=port),
                        status=ScanStatus.FAILED,
                        notes=f"Compatibility test error: {str(e)}",
                    )

                with self._lock:
                    results.append(res)
                    tested += 1

                if result_callback:
                    result_callback(res)

                if progress_callback:
                    progress_callback(tested, total, f"Tested SNI: {sni}")

        return results
