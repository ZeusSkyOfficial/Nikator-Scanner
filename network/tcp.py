"""TCP connectivity tester for Nikator Scanner.
Establishes raw socket connections to probe host:port reachability and measure latency.
"""

from __future__ import annotations

import socket
import time
from typing import Optional
from models.results import TCPResult


class TCPTester:
    """Tests TCP port connectivity and measures connection latency."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def test_connection(self, host_or_ip: str, port: int = 443) -> TCPResult:
        """Attempt TCP 3-way handshake against the target endpoint."""
        target = host_or_ip.strip()
        if not target:
            return TCPResult(connected=False, error="Target host/IP is required")

        start_time = time.perf_counter()
        sock: Optional[socket.socket] = None

        try:
            # Determine address family (IPv4 or IPv6)
            addr_info = socket.getaddrinfo(
                target, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not addr_info:
                return TCPResult(
                    connected=False,
                    port=port,
                    error=f"Could not resolve endpoint {target}:{port}",
                )

            family, socktype, proto, canonname, sockaddr = addr_info[0]
            remote_ip = sockaddr[0]

            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.timeout)

            # Measure TCP handshake latency
            connect_start = time.perf_counter()
            sock.connect(sockaddr)
            latency_ms = (time.perf_counter() - connect_start) * 1000.0

            return TCPResult(
                connected=True,
                remote_ip=remote_ip,
                port=port,
                latency_ms=latency_ms,
            )

        except socket.timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPResult(
                connected=False,
                remote_ip=target,
                port=port,
                latency_ms=elapsed_ms,
                error=f"Connection timed out ({self.timeout}s)",
            )
        except ConnectionRefusedError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPResult(
                connected=False,
                remote_ip=target,
                port=port,
                latency_ms=elapsed_ms,
                error="Connection refused (port closed or filtered)",
            )
        except OSError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPResult(
                connected=False,
                remote_ip=target,
                port=port,
                latency_ms=elapsed_ms,
                error=f"Network error: {e.strerror or str(e)}",
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TCPResult(
                connected=False,
                remote_ip=target,
                port=port,
                latency_ms=elapsed_ms,
                error=f"TCP test error: {str(e)}",
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
