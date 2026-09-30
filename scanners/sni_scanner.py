"""SNI Scanner core engine for Nikator Scanner.
Orchestrates multi-stage diagnostics: candidate discovery, DNS resolution,
TCP reachability, TLS/SNI handshake, certificate inspection, and HTTP verification.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
import json
import logging
from pathlib import Path
import threading
import time
from typing import Callable, List, Optional, Set
import urllib.request

from models.results import (
    ApplicationSettings,
    DNSResult,
    HTTPResult,
    ScanResult,
    ScanSession,
    ScanStatus,
    ScanTarget,
    TCPResult,
    TLSResult,
)
from network.http_client import HTTPTester
from network.resolver import DNSResolver
from network.tcp import TCPTester
from network.tls import TLSTester
from utils.validation import is_valid_domain, normalize_domain

logger = logging.getLogger("NikatorScanner.SNIScanner")


class SNIScanner:
    """Multi-stage SNI and subdomain diagnostic scanning pipeline."""

    def __init__(self, settings: Optional[ApplicationSettings] = None) -> None:
        self.settings = settings or ApplicationSettings()
        self.dns_resolver = DNSResolver(
            timeout=self.settings.dns_timeout,
            custom_servers=self.settings.custom_dns_servers,
        )
        self.tcp_tester = TCPTester(timeout=self.settings.tcp_timeout)
        self.tls_tester = TLSTester(timeout=self.settings.tls_timeout)
        self.http_tester = HTTPTester(timeout=self.settings.http_timeout)

        self._is_paused = threading.Event()
        self._is_paused.set()  # set means running (not paused)
        self._is_cancelled = threading.Event()
        self._lock = threading.Lock()

    def pause(self) -> None:
        """Pause active scan pipeline."""
        self._is_paused.clear()

    def resume(self) -> None:
        """Resume paused scan pipeline."""
        self._is_paused.set()

    def cancel(self) -> None:
        """Signal immediate cancellation to workers."""
        self._is_cancelled.set()
        self._is_paused.set()  # unblock if paused so threads can exit

    @property
    def is_cancelled(self) -> bool:
        return self._is_cancelled.is_set()

    @property
    def is_paused(self) -> bool:
        return not self._is_paused.is_set()

    def discover_candidates(
        self,
        domain: str,
        limit: int = 100,
        source: str = "all",
        user_wordlist: Optional[List[str]] = None,
    ) -> List[ScanTarget]:
        """Generate candidate hostnames for the specified domain."""
        clean_domain = normalize_domain(domain)
        if not clean_domain:
            return []

        candidates: Set[str] = {clean_domain, f"www.{clean_domain}"}

        # 1. User provided list
        if user_wordlist:
            for sub in user_wordlist:
                sub = sub.strip().lower()
                if sub:
                    candidates.add(f"{sub}.{clean_domain}" if not sub.endswith(f".{clean_domain}") else sub)

        # 2. Public / Built-in Wordlist
        wordlist_path = Path(__file__).resolve().parent.parent / "data" / "datasets" / "subdomains.txt"
        if wordlist_path.exists() and source in ("all", "builtin", "public"):
            try:
                with open(wordlist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        sub = line.strip().lower()
                        if sub and not sub.startswith("#"):
                            candidates.add(f"{sub}.{clean_domain}")
                            if len(candidates) >= limit * 2:
                                break
            except Exception as e:
                logger.warning(f"Error reading subdomains dataset: {e}")

        # 3. Optional public Certificate Transparency query (crt.sh)
        if source in ("all", "crtsh", "public") and len(candidates) < limit:
            crt_subs = self._fetch_crtsh_subdomains(clean_domain)
            for sub in crt_subs:
                candidates.add(sub)
                if len(candidates) >= limit * 2:
                    break

        sorted_candidates = sorted(
            candidates,
            key=lambda x: (x.count("."), len(x), x),
        )[:limit]

        targets = [
            ScanTarget(
                hostname=h,
                port=443,
                sni=h,
                protocol="https",
                source=source,
            )
            for h in sorted_candidates
        ]
        return targets

    def _fetch_crtsh_subdomains(self, domain: str) -> List[str]:
        """Fetch discovered names from public Certificate Transparency logs via crt.sh."""
        discovered: Set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NikatorScanner/1.0", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for name in name_val.split("\n"):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(domain) and is_valid_domain(name):
                                discovered.add(name)
        except Exception:
            # Public CT lookup is opportunistic; fail silently to built-in wordlist
            pass
        return list(discovered)

    def scan_single(self, target: ScanTarget) -> ScanResult:
        """Execute full multi-stage diagnostic pipeline on a single target."""
        result = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
        )

        # Stage 1: DNS Resolution
        dns_res = self.dns_resolver.resolve(target.hostname)
        result.dns = dns_res

        if not dns_res.resolved:
            result.status = ScanStatus.FAILED
            result.total_latency_ms = dns_res.latency_ms
            return result

        # Determine target IP address for network probes
        primary_ip = target.ip or dns_res.primary_ip
        if not primary_ip:
            result.status = ScanStatus.FAILED
            result.total_latency_ms = dns_res.latency_ms
            result.dns.error = "No IPv4/IPv6 addresses discovered"
            return result

        # Stage 2: TCP Connectivity
        tcp_res = self.tcp_tester.test_connection(primary_ip, target.port)
        result.tcp = tcp_res

        if not tcp_res.connected:
            result.status = ScanStatus.FAILED
            result.total_latency_ms = dns_res.latency_ms + tcp_res.latency_ms
            return result

        # Stage 3: TLS Handshake & SNI Verification
        tls_res = self.tls_tester.test_tls(
            primary_ip,
            target.port,
            sni=target.sni or target.hostname,
        )
        result.tls = tls_res

        # Stage 4: HTTP / HTTPS probe
        http_res = self.http_tester.probe(
            host_or_ip=primary_ip,
            port=target.port,
            use_tls=True,
            sni=target.sni or target.hostname,
        )
        result.http = http_res

        # Calculate final latency & status
        total_lat = (
            (dns_res.latency_ms if dns_res.resolved else 0.0)
            + (tcp_res.latency_ms if tcp_res.connected else 0.0)
            + (tls_res.latency_ms if tls_res.handshake_success else 0.0)
        )
        result.total_latency_ms = total_lat
        result.status = result.calculate_status()

        return result

    def scan_targets(
        self,
        targets: List[ScanTarget],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        batch_finished_callback: Optional[Callable[[ScanSession, List[ScanResult]], None]] = None,
    ) -> List[ScanResult]:
        """Execute scan across targets with concurrency, pause/resume, and cancellation."""
        self._is_cancelled.clear()
        self._is_paused.set()

        total = len(targets)
        results: List[ScanResult] = []
        tested_count = 0
        success_count = 0
        failed_count = 0
        total_latency = 0.0

        session = ScanSession(
            scan_type="SNI Scanner",
            target_domain=targets[0].hostname if targets else "",
            started_at=datetime.now().isoformat(),
            total_tested=total,
        )

        max_workers = min(self.settings.max_concurrency, max(1, total))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {}
            for target in targets:
                if self.is_cancelled:
                    break
                future = executor.submit(self._worker_wrapper, target)
                future_to_target[future] = target

            for future in concurrent.futures.as_completed(future_to_target):
                if self.is_cancelled:
                    break

                # Handle pause
                self._is_paused.wait()

                target = future_to_target[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = ScanResult(
                        target=target,
                        status=ScanStatus.FAILED,
                        notes=f"Internal scan error: {str(e)}",
                    )

                with self._lock:
                    results.append(res)
                    tested_count += 1
                    if res.status == ScanStatus.SUCCESS:
                        success_count += 1
                    elif res.status == ScanStatus.FAILED:
                        failed_count += 1
                    if res.total_latency_ms > 0:
                        total_latency += res.total_latency_ms

                if result_callback:
                    result_callback(res)

                if progress_callback:
                    current_op = f"Testing {target.hostname}..."
                    progress_callback(tested_count, total, current_op)

                if self.settings.rate_limit_delay_ms > 0:
                    time.sleep(self.settings.rate_limit_delay_ms / 1000.0)

        session.completed_at = datetime.now().isoformat()
        session.successful_count = success_count
        session.failed_count = failed_count
        session.avg_latency_ms = (total_latency / tested_count) if tested_count > 0 else 0.0
        session.results = results

        if batch_finished_callback:
            batch_finished_callback(session, results)

        return results

    def _worker_wrapper(self, target: ScanTarget) -> ScanResult:
        """Internal worker checking pause and cancellation."""
        self._is_paused.wait()
        if self.is_cancelled:
            return ScanResult(target=target, status=ScanStatus.CANCELLED)
        return self.scan_single(target)
