"""DNS scanner engine for batch hostname resolution.
"""

from __future__ import annotations

import concurrent.futures
from typing import Callable, List, Optional
from models.results import DNSResult, ScanTarget
from network.resolver import DNSResolver


class DNSScanner:
    """Performs concurrent DNS resolution across target hostnames."""

    def __init__(
        self,
        resolver: Optional[DNSResolver] = None,
        max_workers: int = 25,
    ) -> None:
        self.resolver = resolver or DNSResolver()
        self.max_workers = max_workers

    def scan_target(self, target: ScanTarget) -> DNSResult:
        """Resolve a single target hostname."""
        return self.resolver.resolve(target.hostname)

    def scan_batch(
        self,
        targets: List[ScanTarget],
        callback: Optional[Callable[[ScanTarget, DNSResult], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None,
    ) -> List[DNSResult]:
        """Resolve a batch of targets concurrently with optional callback."""
        results: List[DNSResult] = []

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
                    res = DNSResult(resolved=False, error=str(e))
                results.append(res)
                if callback:
                    callback(target, res)

        return results
