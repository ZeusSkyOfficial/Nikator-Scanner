"""TLS scanner engine for concurrent SSL/TLS handshake and SNI validation.
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, List, Optional
from models.results import TLSResult, ScanTarget
from network.tls import TLSTester


class TLSScanner:
    """Performs concurrent TLS handshakes and SNI compatibility tests."""

    def __init__(
        self,
        tester: Optional[TLSTester] = None,
        max_workers: int = 25,
    ) -> None:
        self.tester = tester or TLSTester()
        self.max_workers = max_workers

    def scan_target(self, target: ScanTarget) -> TLSResult:
        """Test TLS handshake for a target."""
        host = target.ip if target.ip else target.hostname
        sni = target.sni or target.hostname
        return self.tester.test_tls(host, target.port, sni=sni)

    def scan_batch(
        self,
        targets: List[ScanTarget],
        callback: Optional[Callable[[ScanTarget, TLSResult], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[TLSResult]:
        """Test TLS on a batch of targets concurrently with optional callback."""
        results: List[TLSResult] = []

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
                    res = TLSResult(handshake_success=False, error=str(e))
                results.append(res)
                if callback:
                    callback(target, res)

        return results
