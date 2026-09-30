"""TCP scanner engine for concurrent port connectivity testing.
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, List, Optional
from models.results import TCPResult, ScanTarget
from network.tcp import TCPTester


class TCPScanner:
    """Performs concurrent TCP connection testing across target endpoints."""

    def __init__(
        self,
        tester: Optional[TCPTester] = None,
        max_workers: int = 25,
    ) -> None:
        self.tester = tester or TCPTester()
        self.max_workers = max_workers

    def scan_target(self, target: ScanTarget) -> TCPResult:
        """Test TCP reachability for a target."""
        host = target.ip if target.ip else target.hostname
        return self.tester.test_connection(host, target.port)

    def scan_batch(
        self,
        targets: List[ScanTarget],
        callback: Optional[Callable[[ScanTarget, TCPResult], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[TCPResult]:
        """Test a batch of targets concurrently with optional callback."""
        results: List[TCPResult] = []

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
                    res = TCPResult(connected=False, error=str(e))
                results.append(res)
                if callback:
                    callback(target, res)

        return results
