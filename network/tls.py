"""TLS / SNI probe and X.509 certificate inspection engine for Nikator Scanner.
Performs real SSL/TLS handshakes with custom SNI, negotiates ciphers/protocols,
and parses detailed X.509 certificate metadata using cryptography.x509.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import hashlib
import ipaddress
import socket
import ssl
import time
from typing import List, Optional, Tuple

from models.results import CertificateInfo, TLSResult

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class TLSTester:
    """Performs TLS handshakes with arbitrary SNI values and inspects certificates."""

    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout

    def test_tls(
        self,
        host_or_ip: str,
        port: int = 443,
        sni: Optional[str] = None,
        verify_cert: bool = False,
    ) -> TLSResult:
        """Execute a TLS handshake to the target host/IP using the specified SNI."""
        target_host = host_or_ip.strip()
        sni_header = (sni or target_host).strip()

        # Build SSL Context
        context = ssl.create_default_context()
        # Diagnostic mode allows handshake to complete even on self-signed/expired certs
        # while still capturing full peer certificate metadata
        if not verify_cert:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Enable ALPN for HTTP/2 and HTTP/1.1 negotiation
        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except (NotImplementedError, AttributeError):
            pass

        start_time = time.perf_counter()
        raw_sock: Optional[socket.socket] = None
        ssl_sock: Optional[ssl.SSLSocket] = None

        try:
            # Resolve destination socket address
            addr_info = socket.getaddrinfo(
                target_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not addr_info:
                return TLSResult(
                    handshake_success=False,
                    sni_used=sni_header,
                    error=f"Could not resolve {target_host}:{port}",
                )

            family, socktype, proto, _, sockaddr = addr_info[0]

            raw_sock = socket.socket(family, socktype, proto)
            raw_sock.settimeout(self.timeout)
            raw_sock.connect(sockaddr)

            # Wrap socket with SSL and apply custom SNI
            ssl_sock = context.wrap_socket(
                raw_sock,
                server_hostname=sni_header if sni_header else None,
                do_handshake_on_connect=False,
            )
            ssl_sock.settimeout(self.timeout)

            handshake_start = time.perf_counter()
            ssl_sock.do_handshake()
            handshake_latency_ms = (time.perf_counter() - handshake_start) * 1000.0

            # Extract negotiated TLS details
            tls_version = ssl_sock.version() or "TLS"
            cipher_info = ssl_sock.cipher()
            cipher_name = cipher_info[0] if cipher_info else "Unknown"
            alpn = ssl_sock.selected_alpn_protocol() or ""

            # Extract DER certificate and parse metadata
            der_cert = ssl_sock.getpeercert(binary_form=True)
            cert_info = self._parse_certificate(der_cert)

            # Check if certificate matches the SNI
            cert_matches = self._check_cert_matches_sni(cert_info, sni_header)

            return TLSResult(
                handshake_success=True,
                sni_used=sni_header,
                tls_version=tls_version,
                cipher=cipher_name,
                certificate=cert_info,
                alpn_selected=alpn,
                latency_ms=handshake_latency_ms,
                certificate_matches_sni=cert_matches,
            )

        except ssl.SSLCertVerificationError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TLSResult(
                handshake_success=False,
                sni_used=sni_header,
                latency_ms=elapsed_ms,
                error=f"Certificate verification error: {e.verify_message}",
            )
        except ssl.SSLError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TLSResult(
                handshake_success=False,
                sni_used=sni_header,
                latency_ms=elapsed_ms,
                error=f"TLS handshake failed: {e.reason or str(e)}",
            )
        except socket.timeout:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TLSResult(
                handshake_success=False,
                sni_used=sni_header,
                latency_ms=elapsed_ms,
                error=f"TLS connection timed out ({self.timeout}s)",
            )
        except ConnectionResetError:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TLSResult(
                handshake_success=False,
                sni_used=sni_header,
                latency_ms=elapsed_ms,
                error="Connection reset by peer during TLS handshake (possible SNI rejection)",
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return TLSResult(
                handshake_success=False,
                sni_used=sni_header,
                latency_ms=elapsed_ms,
                error=f"TLS test error: {str(e)}",
            )
        finally:
            if ssl_sock is not None:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif raw_sock is not None:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def _parse_certificate(self, der_cert: Optional[bytes]) -> CertificateInfo:
        """Parse raw DER-encoded certificate into CertificateInfo."""
        if not der_cert:
            return CertificateInfo(error="No certificate presented by server")

        sha256_fp = hashlib.sha256(der_cert).hexdigest()
        formatted_fp = ":".join(sha256_fp[i : i + 2].upper() for i in range(0, len(sha256_fp), 2))

        if not HAS_CRYPTOGRAPHY:
            return CertificateInfo(
                fingerprint_sha256=formatted_fp,
                error="Cryptography package not available for deep X.509 parsing",
            )

        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())

            # Subject
            subject_parts = []
            for attr in cert.subject:
                oid_name = attr.oid._name
                subject_parts.append(f"{oid_name}={attr.value}")
            subject_str = ", ".join(subject_parts)

            # Issuer
            issuer_parts = []
            for attr in cert.issuer:
                oid_name = attr.oid._name
                issuer_parts.append(f"{oid_name}={attr.value}")
            issuer_str = ", ".join(issuer_parts)

            # Subject Alternative Names (SANs)
            sans: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        sans.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        sans.append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            # Validity Dates
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                # Python cryptography older fallback
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            now_utc = datetime.now(timezone.utc)
            is_valid = not_before <= now_utc <= not_after
            is_expired = now_utc > not_after

            # Serial and Signature
            serial_hex = hex(cert.serial_number)[2:].upper()
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"

            # Raw PEM conversion
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

            return CertificateInfo(
                subject=subject_str,
                issuer=issuer_str,
                subject_alt_names=sans,
                valid_from=not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                valid_until=not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                is_valid=is_valid,
                is_expired=is_expired,
                signature_algorithm=sig_algo,
                serial_number=serial_hex,
                fingerprint_sha256=formatted_fp,
                raw_pem=pem_cert,
            )
        except Exception as e:
            return CertificateInfo(
                fingerprint_sha256=formatted_fp,
                error=f"Certificate parsing failed: {str(e)}",
            )

    def _check_cert_matches_sni(self, cert_info: CertificateInfo, sni: str) -> bool:
        """Verify if certificate SANs or Common Name match the requested SNI."""
        if not sni:
            return False
        clean_sni = sni.lower().strip()

        candidates = list(cert_info.subject_alt_names)
        # Add Common Name from Subject if present
        if "commonName=" in cert_info.subject:
            for part in cert_info.subject.split(","):
                part = part.strip()
                if part.startswith("commonName="):
                    candidates.append(part.replace("commonName=", "").strip())

        for pattern in candidates:
            pattern_clean = pattern.lower().strip()
            if pattern_clean == clean_sni:
                return True
            # Check wildcard e.g. *.example.com
            if pattern_clean.startswith("*."):
                suffix = pattern_clean[2:]
                # Matches foo.example.com but not bar.foo.example.com
                if clean_sni.endswith("." + suffix):
                    sub_part = clean_sni[: -(len(suffix) + 1)]
                    if "." not in sub_part:
                        return True
            if fnmatch.fnmatch(clean_sni, pattern_clean):
                return True

        return False
