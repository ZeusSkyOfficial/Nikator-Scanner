"""Validation routines for domain names, IP addresses, ports, and network targets.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# RFC 1035 / 1123 compliant domain regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def is_valid_ipv4(address: str) -> bool:
    """Check if address is a valid IPv4 address."""
    if not address or not isinstance(address, str):
        return False
    try:
        ip = ipaddress.IPv4Address(address.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(address: str) -> bool:
    """Check if address is a valid IPv6 address."""
    if not address or not isinstance(address, str):
        return False
    try:
        ip = ipaddress.IPv6Address(address.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(address: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    return is_valid_ipv4(address) or is_valid_ipv6(address)


def is_valid_port(port: int | str) -> bool:
    """Check if port is within valid TCP/UDP range [1, 65535]."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def normalize_domain(raw_input: str) -> str:
    """Clean and normalize a domain or URL to just the hostname."""
    if not raw_input:
        return ""
    text = raw_input.strip().lower()
    # Strip URL schemes if present
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or text
    # Strip trailing slashes, paths, and ports
    text = text.split("/")[0]
    if ":" in text and not text.startswith("["):  # avoid splitting IPv6 without brackets
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def is_valid_domain(domain: str) -> bool:
    """Check if the provided string is a valid, resolvable domain format."""
    normalized = normalize_domain(domain)
    if not normalized or len(normalized) > 253:
        return False
    # Localhost exception
    if normalized == "localhost":
        return True
    return bool(DOMAIN_REGEX.match(normalized))


def extract_host_port(target_str: str, default_port: int = 443) -> Tuple[str, int]:
    """Parse string formatted as host, host:port, [ipv6]:port, or URL."""
    text = target_str.strip()
    if not text:
        return "", default_port

    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname or ""
        port = parsed.port or default_port
        return host, port

    # Check for IPv6 bracket notation [2001:db8::1]:443
    if text.startswith("["):
        bracket_end = text.find("]")
        if bracket_end != -1:
            host = text[1:bracket_end]
            remainder = text[bracket_end + 1:]
            if remainder.startswith(":"):
                port_str = remainder[1:]
                port = int(port_str) if is_valid_port(port_str) else default_port
            else:
                port = default_port
            return host, port

    # Standard host:port
    if ":" in text:
        parts = text.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            port = int(parts[1]) if is_valid_port(parts[1]) else default_port
            return parts[0].strip(), port

    return text, default_port
