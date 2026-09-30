"""HTTP/HTTPS scanner engine for concurrent status and header verification.
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, List, Optional
from models.results import HTTPResult, ScanTarget
from network.http_client import HTTPTester


class HTTPScanner:
    """Performs concurrent HTTP/HTTPS probing across target endpoints."""

    def __init__(
        self,
        tester: Optional[HTTPTester] = None,
        max_workers: int = 25,
    ) -> None:
        self.tester = tester or HTTPTester()
        self.max_workers = max_workers

    def scan_target(self, target: ScanTarget) -> HTTPResult:
        """Probe HTTP/HTTPS for a target."""
        host = target.ip if target.ip else target.hostname
        use_tls = target.port in (443, 8443) or target.protocol in ("https", "tls")
        return self.tester.probe(
            host_or_ip=host,
            port=target.port,
            use_tls=use_tls,
            sni=target.sni or target.hostname,
        )

    def scan_batch(
        self,
        targets: List[ScanTarget],
        callback: Optional[Callable[[ScanTarget, HTTPResult], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[HTTPResult]:
        """Probe a batch of targets concurrently with optional callback."""
        results: List[HTTPResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {}
            for target in targets:
                if is_cancelled and is_cancelled():
                    break
                future = executor.submit(self.scan_target, target)
                future_to_target[future] = target

            for future in concurrent.futures.as_completed(future_to_target):
                if is_cancelled and is_cancelled():
                    break
                target = future_to_target[future]
                try:
                    res = future.result()
                except Exception as e:
                    res = HTTPResult(reachable=False, error=str(e))
                results.append(res)
                if callback:
                    callback(target, res)

        return results
