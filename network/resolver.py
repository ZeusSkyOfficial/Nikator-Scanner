"""DNS resolution engine for Nikator Scanner.
Utilizes dnspython for advanced record querying (A, AAAA, CNAME) with standard
socket fallback and precise latency timing.
"""

from __future__ import annotations

import socket
import time
from typing import List, Optional
from models.results import DNSResult

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class DNSResolver:
    """Performs DNS lookups and measures resolution latency."""

    def __init__(
        self,
        timeout: float = 3.0,
        custom_servers: Optional[List[str]] = None,
    ) -> None:
        self.timeout = timeout
        self.custom_servers = custom_servers or []

    def resolve(self, hostname: str) -> DNSResult:
        """Resolve A, AAAA, and CNAME records for the given hostname."""
        target = hostname.strip().rstrip(".")
        if not target:
            return DNSResult(error="Empty hostname provided")

        # Check if already an IP
        try:
            socket.inet_aton(target)
            return DNSResult(
                resolved=True,
                ipv4_addresses=[target],
                latency_ms=0.1,
            )
        except OSError:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, target)
            return DNSResult(
                resolved=True,
                ipv6_addresses=[target],
                latency_ms=0.1,
            )
        except (OSError, AttributeError):
            pass

        if HAS_DNSPYTHON:
            return self._resolve_dnspython(target)
        return self._resolve_socket(target)

    def _resolve_dnspython(self, hostname: str) -> DNSResult:
        start_time = time.perf_counter()
        resolver = dns.resolver.Resolver(configure=not bool(self.custom_servers))
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout

        if self.custom_servers:
            resolver.nameservers = self.custom_servers

        ipv4_addrs: List[str] = []
        ipv6_addrs: List[str] = []
        cnames: List[str] = []
        errors: List[str] = []

        # Query A records
        try:
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                ipv4_addrs.append(rdata.to_text())
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            errors.append(f"A: {type(e).__name__}")

        # Query AAAA records
        try:
            answers = resolver.resolve(hostname, "AAAA")
            for rdata in answers:
                ipv6_addrs.append(rdata.to_text())
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            errors.append(f"AAAA: {type(e).__name__}")

        # Query CNAME records
        try:
            answers = resolver.resolve(hostname, "CNAME")
            for rdata in answers:
                cnames.append(rdata.to_text().rstrip("."))
        except Exception:
            pass

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        if ipv4_addrs or ipv6_addrs or cnames:
            return DNSResult(
                resolved=True,
                ipv4_addresses=ipv4_addrs,
                ipv6_addresses=ipv6_addrs,
                cnames=cnames,
                latency_ms=elapsed_ms,
                nameservers=resolver.nameservers,
            )

        # If dnspython found nothing or errored, try system socket fallback
        fallback_res = self._resolve_socket(hostname)
        if fallback_res.resolved:
            return fallback_res

        err_msg = ", ".join(errors) if errors else "Host name could not be resolved (NXDOMAIN/No Answer)"
        return DNSResult(
            resolved=False,
            latency_ms=elapsed_ms,
            error=err_msg,
            nameservers=resolver.nameservers,
        )

    def _resolve_socket(self, hostname: str) -> DNSResult:
        start_time = time.perf_counter()
        ipv4_addrs: List[str] = []
        ipv6_addrs: List[str] = []

        try:
            addr_info = socket.getaddrinfo(
                hostname, None, proto=socket.IPPROTO_TCP
            )
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ipv4_addrs:
                    ipv4_addrs.append(ip)
                elif family == socket.AF_INET6 and ip not in ipv6_addrs:
                    ipv6_addrs.append(ip)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if ipv4_addrs or ipv6_addrs:
                return DNSResult(
                    resolved=True,
                    ipv4_addresses=ipv4_addrs,
                    ipv6_addresses=ipv6_addrs,
                    latency_ms=elapsed_ms,
                )
            return DNSResult(
                resolved=False,
                latency_ms=elapsed_ms,
                error="No IP addresses returned by system resolver",
            )
        except socket.gaierror as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DNSResult(
                resolved=False,
                latency_ms=elapsed_ms,
                error=f"DNS resolution failed: {e.strerror or str(e)}",
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return DNSResult(
                resolved=False,
                latency_ms=elapsed_ms,
                error=f"DNS resolution error: {str(e)}",
            )
