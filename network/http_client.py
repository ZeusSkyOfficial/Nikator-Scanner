"""HTTP and HTTPS probing engine for Nikator Scanner.
Utilizes httpx for asynchronous / synchronous HTTP diagnostics with custom headers,
redirect tracking, and response header extraction.
"""

from __future__ import annotations

import time
from typing import Dict, Optional
from models.results import HTTPResult

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

import urllib.request
import urllib.error


class HTTPTester:
    """Probes HTTP/HTTPS endpoints and extracts status codes and server headers."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def probe(
        self,
        host_or_ip: str,
        port: int = 443,
        use_tls: bool = True,
        sni: Optional[str] = None,
        path: str = "/",
    ) -> HTTPResult:
        """Perform an HTTP or HTTPS probe against target."""
        scheme = "https" if use_tls else "http"
        sni_header = (sni or host_or_ip).strip()

        # Build probe URL
        if (use_tls and port == 443) or (not use_tls and port == 80):
            url = f"{scheme}://{host_or_ip}{path}"
        else:
            url = f"{scheme}://{host_or_ip}:{port}{path}"

        start_time = time.perf_counter()

        if HAS_HTTPX:
            return self._probe_httpx(url, host_or_ip, sni_header, start_time)
        return self._probe_urllib(url, host_or_ip, sni_header, start_time)

    def _probe_httpx(
        self,
        url: str,
        host: str,
        sni: str,
        start_time: float,
    ) -> HTTPResult:
        headers = {
            "User-Agent": "NikatorScanner/1.0 (Network Diagnostic Suite)",
            "Host": sni,
            "Accept": "*/*",
        }

        try:
            # Create client with SSL verification disabled for diagnostics
            # and short connect/read timeouts
            with httpx.Client(
                verify=False,
                timeout=httpx.Timeout(self.timeout, connect=self.timeout),
                follow_redirects=False,
                http2=True,
            ) as client:
                req_start = time.perf_counter()
                response = client.get(url, headers=headers)
                latency_ms = (time.perf_counter() - req_start) * 1000.0

                server_hdr = response.headers.get("server", "")
                content_type = response.headers.get("content-type", "")
                content_len = len(response.content) if response.content else 0
                redirect_url = response.headers.get("location", "")
                http_ver = response.http_version

                return HTTPResult(
                    reachable=True,
                    status_code=response.status_code,
                    server_header=server_hdr,
                    content_type=content_type,
                    content_length=content_len,
                    redirect_url=redirect_url,
                    http_version=http_ver,
                    latency_ms=latency_ms,
                    headers=dict(response.headers),
                )
        except httpx.ConnectTimeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPResult(
                reachable=False,
                latency_ms=elapsed_ms,
                error=f"HTTP connection timed out ({self.timeout}s)",
            )
        except httpx.ConnectError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPResult(
                reachable=False,
                latency_ms=elapsed_ms,
                error=f"HTTP connection failed: {str(e)}",
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPResult(
                reachable=False,
                latency_ms=elapsed_ms,
                error=f"HTTP probe error: {str(e)}",
            )

    def _probe_urllib(
        self,
        url: str,
        host: str,
        sni: str,
        start_time: float,
    ) -> HTTPResult:
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "NikatorScanner/1.0",
                "Host": sni,
            },
        )

        try:
            req_start = time.perf_counter()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as response:
                latency_ms = (time.perf_counter() - req_start) * 1000.0
                status = response.status
                headers_dict = dict(response.headers)
                return HTTPResult(
                    reachable=True,
                    status_code=status,
                    server_header=headers_dict.get("Server", ""),
                    content_type=headers_dict.get("Content-Type", ""),
                    latency_ms=latency_ms,
                    headers=headers_dict,
                )
        except urllib.error.HTTPError as e:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPResult(
                reachable=True,
                status_code=e.code,
                server_header=e.headers.get("Server", "") if e.headers else "",
                content_type=e.headers.get("Content-Type", "") if e.headers else "",
                latency_ms=latency_ms,
                headers=dict(e.headers) if e.headers else {},
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HTTPResult(
                reachable=False,
                latency_ms=elapsed_ms,
                error=f"HTTP error: {str(e)}",
            )
