"""Data models for Nikator Scanner.

Defines typed dataclasses and structures for network targets,
diagnostic stages (DNS, TCP, TLS, HTTP), certificates, sessions, and settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ScanStatus(str, Enum):
    """Execution status for scan targets and stages."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    NOT_TESTED = "not_tested"

    @property
    def label(self) -> str:
        mapping = {
            self.PENDING: "Pending",
            self.RUNNING: "Running",
            self.SUCCESS: "Success",
            self.PARTIAL: "Partial",
            self.FAILED: "Failed",
            self.CANCELLED: "Cancelled",
            self.NOT_TESTED: "Not Tested",
        }
        return mapping.get(self, "Unknown")


@dataclass
class ScanTarget:
    """Represents a diagnostic target to be tested."""
    hostname: str
    ip: Optional[str] = None
    port: int = 443
    sni: Optional[str] = None
    protocol: str = "tcp"
    extra_headers: Dict[str, str] = field(default_factory=dict)
    source: str = "input"

    def __post_init__(self) -> None:
        self.hostname = self.hostname.strip()
        if not self.sni:
            self.sni = self.hostname


@dataclass
class DNSResult:
    """Result of DNS resolution stage."""
    resolved: bool = False
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    nameservers: List[str] = field(default_factory=list)
    ttl: int = 0
    error: Optional[str] = None

    @property
    def primary_ip(self) -> str:
        if self.ipv4_addresses:
            return self.ipv4_addresses[0]
        if self.ipv6_addresses:
            return self.ipv6_addresses[0]
        return ""

    @property
    def all_ips(self) -> List[str]:
        return self.ipv4_addresses + self.ipv6_addresses


@dataclass
class TCPResult:
    """Result of TCP connection test."""
    connected: bool = False
    remote_ip: str = ""
    port: int = 443
    latency_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class CertificateInfo:
    """Extracted X.509 certificate metadata."""
    subject: str = ""
    issuer: str = ""
    subject_alt_names: List[str] = field(default_factory=list)
    valid_from: str = ""
    valid_until: str = ""
    is_valid: bool = False
    is_expired: bool = False
    signature_algorithm: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    ocsp_servers: List[str] = field(default_factory=list)
    crl_distribution_points: List[str] = field(default_factory=list)
    raw_pem: str = ""
    error: Optional[str] = None


@dataclass
class TLSResult:
    """Result of TLS handshake and SNI test."""
    handshake_success: bool = False
    sni_used: str = ""
    tls_version: str = ""
    cipher: str = ""
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    alpn_selected: str = ""
    latency_ms: float = 0.0
    certificate_matches_sni: bool = False
    error: Optional[str] = None


@dataclass
class HTTPResult:
    """Result of HTTP/HTTPS probe."""
    reachable: bool = False
    status_code: int = 0
    server_header: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    http_version: str = ""
    latency_ms: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated scan result across all diagnostic stages."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget = field(default_factory=lambda: ScanTarget(""))
    dns: DNSResult = field(default_factory=DNSResult)
    tcp: TCPResult = field(default_factory=TCPResult)
    tls: TLSResult = field(default_factory=TLSResult)
    http: HTTPResult = field(default_factory=HTTPResult)
    status: ScanStatus = ScanStatus.PENDING
    total_latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""

    def calculate_status(self) -> ScanStatus:
        """Derive high-level diagnostic status based on pipeline stage outcomes."""
        if not self.dns.resolved:
            return ScanStatus.FAILED
        if not self.tcp.connected:
            return ScanStatus.FAILED
        if self.tls.handshake_success and (self.http.reachable or self.http.status_code > 0):
            return ScanStatus.SUCCESS
        if self.tls.handshake_success or self.tcp.connected:
            return ScanStatus.PARTIAL
        return ScanStatus.FAILED

    @property
    def display_ip(self) -> str:
        if self.target.ip:
            return self.target.ip
        return self.dns.primary_ip or "N/A"

    @property
    def display_latency(self) -> str:
        if self.total_latency_ms > 0:
            return f"{self.total_latency_ms:.1f} ms"
        if self.tcp.latency_ms > 0:
            return f"{self.tcp.latency_ms:.1f} ms"
        if self.dns.latency_ms > 0:
            return f"{self.dns.latency_ms:.1f} ms"
        return "N/A"


@dataclass
class ScanSession:
    """Historical or active session recording."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: str = "SNI Scanner"
    target_domain: str = ""
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    total_tested: int = 0
    successful_count: int = 0
    failed_count: int = 0
    avg_latency_ms: float = 0.0
    results: List[ScanResult] = field(default_factory=list)


@dataclass
class ApplicationSettings:
    """Application-wide configuration parameters."""
    dns_timeout: float = 3.0
    tcp_timeout: float = 3.0
    tls_timeout: float = 4.0
    http_timeout: float = 4.0
    custom_dns_servers: List[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    max_concurrency: int = 25
    retry_count: int = 1
    rate_limit_delay_ms: int = 0
    theme_mode: str = "dark"  # "dark" or "light"
    compact_table: bool = False
    font_size: int = 12
    enable_logging: bool = True
    log_level: str = "INFO"
    history_retention_days: int = 30
    user_wordlist_path: str = ""
    export_directory: str = ""
