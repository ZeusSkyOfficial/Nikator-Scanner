"""Cloudflare and CDN Clean IP candidate generator for Nikator Scanner.
Provides verified CIDR ranges and generates diverse, high-probability clean IPs
for network configs, VLESS, VMess, Trojan, and CDN-backed endpoints.
"""

from __future__ import annotations

import ipaddress
import random
from typing import List, Optional, Set


# Official Cloudflare IPv4 CIDR blocks
CLOUDFLARE_CIDRS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# Popular high-probability clean subnets tested across Iranian ISPs (MCI, Irancell, Mokhaberat, Shatel)
POPULAR_CLEAN_SUBNETS = [
    "104.16.0.0/20",
    "104.17.0.0/20",
    "104.18.0.0/20",
    "104.19.0.0/20",
    "104.20.0.0/20",
    "104.21.0.0/20",
    "104.22.0.0/20",
    "104.24.0.0/20",
    "104.25.0.0/20",
    "104.26.0.0/20",
    "104.27.0.0/20",
    "172.64.0.0/20",
    "172.65.0.0/20",
    "172.66.0.0/20",
    "172.67.0.0/20",
    "172.68.0.0/20",
    "172.69.0.0/20",
    "172.70.0.0/20",
    "172.71.0.0/20",
    "162.159.0.0/20",
    "198.41.128.0/20",
    "188.114.96.0/22",
    "108.162.192.0/20",
]

# Curated seed list of known low-latency, active Anycast edge nodes
SEED_CLEAN_IPS = [
    "104.16.148.22", "104.16.149.22", "104.16.208.18", "104.16.209.18",
    "104.17.152.42", "104.17.153.42", "104.17.209.9", "104.17.210.9",
    "104.18.10.15", "104.18.11.15", "104.18.21.226", "104.18.22.226",
    "104.19.141.15", "104.19.142.15", "104.20.50.81", "104.20.51.81",
    "104.21.48.1", "104.21.52.12", "104.22.10.1", "104.22.11.1",
    "104.24.10.1", "104.24.11.1", "104.25.10.1", "104.25.11.1",
    "104.26.10.1", "104.26.11.1", "104.27.10.1", "104.27.11.1",
    "172.64.150.1", "172.64.151.1", "172.65.10.1", "172.65.11.1",
    "172.66.40.1", "172.66.41.1", "172.67.180.25", "172.67.182.11",
    "172.68.10.1", "172.68.11.1", "172.69.10.1", "172.69.11.1",
    "172.70.10.1", "172.70.11.1", "172.71.10.1", "172.71.11.1",
    "162.159.192.1", "162.159.193.1", "162.159.195.1",
    "198.41.129.1", "198.41.130.1", "198.41.214.162",
    "188.114.96.1", "188.114.97.2", "188.114.98.3", "188.114.99.4",
    "108.162.192.1", "108.162.193.1", "141.101.64.1", "141.101.65.1",
]


def _sample_ip_from_cidr(cidr_str: str) -> str:
    """Generate a random valid host IPv4 address from a CIDR block."""
    try:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
        num_hosts = net.num_addresses
        if num_hosts <= 2:
            return str(net.network_address)
        # Avoid network (.0) and broadcast (.255)
        offset = random.randint(1, num_hosts - 2)
        return str(net.network_address + offset)
    except Exception:
        return "104.16.1.1"


def get_candidate_clean_ips(
    resolved_ips: Optional[List[str]] = None,
    count: int = 50,
    include_cloudflare_ranges: bool = True,
) -> List[str]:
    """Generate a diverse, prioritized list of candidate clean IPs.

    Args:
        resolved_ips: Direct DNS resolved IPs for the config domain (highest priority).
        count: Desired total number of candidate IPs to test.
        include_cloudflare_ranges: Whether to include Cloudflare Anycast CIDRs.

    Returns:
        List of unique candidate IP strings.
    """
    candidates: List[str] = []
    seen: Set[str] = set()

    def add_ip(ip_str: str) -> None:
        clean = ip_str.strip()
        if clean and clean not in seen:
            try:
                # Validate it's a valid IPv4 address
                ipaddress.IPv4Address(clean)
                seen.add(clean)
                candidates.append(clean)
            except Exception:
                pass

    # 1. First priority: Direct DNS resolved IPs from the config domain
    if resolved_ips:
        for ip in resolved_ips:
            add_ip(ip)

    if not include_cloudflare_ranges:
        return candidates[:count]

    # 2. Second priority: High-probability seed clean IPs (shuffled)
    seeds = list(SEED_CLEAN_IPS)
    random.shuffle(seeds)
    for ip in seeds:
        add_ip(ip)
        if len(candidates) >= count:
            return candidates[:count]

    # 3. Third priority: Sample diverse IPs across popular clean subnets
    subnets = list(POPULAR_CLEAN_SUBNETS)
    random.shuffle(subnets)
    for subnet in subnets:
        for _ in range(4):
            add_ip(_sample_ip_from_cidr(subnet))
            if len(candidates) >= count:
                return candidates[:count]

    # 4. Fourth priority: General Cloudflare CIDR blocks
    all_cidrs = list(CLOUDFLARE_CIDRS)
    random.shuffle(all_cidrs)
    attempts = 0
    while len(candidates) < count and attempts < count * 5:
        attempts += 1
        cidr = random.choice(all_cidrs)
        add_ip(_sample_ip_from_cidr(cidr))

    return candidates[:count]
