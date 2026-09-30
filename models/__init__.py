"""Models package for Nikator Scanner."""
from .results import (
    ScanStatus,
    ScanTarget,
    DNSResult,
    TCPResult,
    CertificateInfo,
    TLSResult,
    HTTPResult,
    ScanResult,
    ScanSession,
    ApplicationSettings,
)

__all__ = [
    "ScanStatus",
    "ScanTarget",
    "DNSResult",
    "TCPResult",
    "CertificateInfo",
    "TLSResult",
    "HTTPResult",
    "ScanResult",
    "ScanSession",
    "ApplicationSettings",
]
