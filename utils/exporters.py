"""Export utilities for Nikator Scanner results.
Supports exporting scan results to TXT, CSV, and JSON formats.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List
from models.results import ScanResult


def export_to_json(results: List[ScanResult], file_path: str | Path) -> bool:
    """Export list of ScanResults to a formatted JSON file."""
    data = []
    for r in results:
        data.append({
            "id": r.id,
            "target": {
                "hostname": r.target.hostname,
                "ip": r.target.ip,
                "port": r.target.port,
                "sni": r.target.sni,
                "protocol": r.target.protocol,
            },
            "status": r.status.value,
            "total_latency_ms": round(r.total_latency_ms, 2),
            "timestamp": r.timestamp,
            "dns": {
                "resolved": r.dns.resolved,
                "ipv4": r.dns.ipv4_addresses,
                "ipv6": r.dns.ipv6_addresses,
                "cnames": r.dns.cnames,
                "latency_ms": round(r.dns.latency_ms, 2),
                "error": r.dns.error,
            },
            "tcp": {
                "connected": r.tcp.connected,
                "remote_ip": r.tcp.remote_ip,
                "port": r.tcp.port,
                "latency_ms": round(r.tcp.latency_ms, 2),
                "error": r.tcp.error,
            },
            "tls": {
                "handshake_success": r.tls.handshake_success,
                "tls_version": r.tls.tls_version,
                "cipher": r.tls.cipher,
                "sni_used": r.tls.sni_used,
                "latency_ms": round(r.tls.latency_ms, 2),
                "certificate_matches_sni": r.tls.certificate_matches_sni,
                "certificate": {
                    "subject": r.tls.certificate.subject,
                    "issuer": r.tls.certificate.issuer,
                    "subject_alt_names": r.tls.certificate.subject_alt_names,
                    "valid_from": r.tls.certificate.valid_from,
                    "valid_until": r.tls.certificate.valid_until,
                    "is_valid": r.tls.certificate.is_valid,
                    "signature_algorithm": r.tls.certificate.signature_algorithm,
                    "serial_number": r.tls.certificate.serial_number,
                },
                "error": r.tls.error,
            },
            "http": {
                "reachable": r.http.reachable,
                "status_code": r.http.status_code,
                "server": r.http.server_header,
                "content_type": r.http.content_type,
                "redirect_url": r.http.redirect_url,
                "http_version": r.http.http_version,
                "latency_ms": round(r.http.latency_ms, 2),
                "error": r.http.error,
            },
        })

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return True


def export_to_csv(results: List[ScanResult], file_path: str | Path) -> bool:
    """Export list of ScanResults to standard CSV table."""
    headers = [
        "Hostname",
        "SNI",
        "IP Address",
        "Port",
        "Status",
        "Latency (ms)",
        "DNS Resolved",
        "DNS Latency (ms)",
        "TCP Connected",
        "TCP Latency (ms)",
        "TLS Success",
        "TLS Version",
        "Cipher",
        "Cert Subject",
        "Cert Issuer",
        "Cert Valid Until",
        "Cert Matches SNI",
        "HTTP Status",
        "HTTP Server",
        "Timestamp",
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in results:
            writer.writerow([
                r.target.hostname,
                r.target.sni,
                r.display_ip,
                r.target.port,
                r.status.label,
                f"{r.total_latency_ms:.1f}" if r.total_latency_ms > 0 else "N/A",
                "Yes" if r.dns.resolved else "No",
                f"{r.dns.latency_ms:.1f}",
                "Yes" if r.tcp.connected else "No",
                f"{r.tcp.latency_ms:.1f}",
                "Yes" if r.tls.handshake_success else "No",
                r.tls.tls_version or "N/A",
                r.tls.cipher or "N/A",
                r.tls.certificate.subject or "N/A",
                r.tls.certificate.issuer or "N/A",
                r.tls.certificate.valid_until or "N/A",
                "Yes" if r.tls.certificate_matches_sni else "No",
                r.http.status_code if r.http.status_code > 0 else "N/A",
                r.http.server_header or "N/A",
                r.timestamp,
            ])
    return True


def export_to_txt(results: List[ScanResult], file_path: str | Path) -> bool:
    """Export list of ScanResults to human-readable plain text report."""
    lines = [
        "=======================================================================",
        "                 Nikator Scanner - Diagnostic Report                   ",
        "        Nikator Team • All Rights Reserved • Telegram: @Zeusskyofficial",
        " تمامی حقوق این برنامه برای تیم نیکاتور میباشد و هر گونه کپی برداری از ان ",
        " دامن شما را خواهد گرفت و به خاک سیاه خواهد نشاند با تشکر تیم نیکاتور     ",
        "=======================================================================",
        f"Total Results: {len(results)}",
        f"Generated: {results[0].timestamp if results else 'N/A'}",
        "-----------------------------------------------------------------------",
        "",
    ]

    for idx, r in enumerate(results, 1):
        lines.append(f"[{idx:03d}] Hostname / SNI : {r.target.hostname} (SNI: {r.target.sni})")
        lines.append(f"      IP Address     : {r.display_ip}:{r.target.port}")
        lines.append(f"      Overall Status : {r.status.label.upper()} (Latency: {r.display_latency})")
        lines.append(f"      DNS Stage      : {'Resolved' if r.dns.resolved else 'Failed'} ({', '.join(r.dns.all_ips) or r.dns.error or 'None'})")
        lines.append(f"      TCP Stage      : {'Connected' if r.tcp.connected else 'Failed'} (Latency: {r.tcp.latency_ms:.1f}ms, Error: {r.tcp.error or 'None'})")
        lines.append(f"      TLS Stage      : {'Success' if r.tls.handshake_success else 'Failed'} ({r.tls.tls_version} {r.tls.cipher})")
        if r.tls.certificate.subject:
            lines.append(f"      Certificate    : Subject: {r.tls.certificate.subject}")
            lines.append(f"                       Issuer: {r.tls.certificate.issuer}")
            lines.append(f"                       Valid: {r.tls.certificate.valid_from} to {r.tls.certificate.valid_until}")
            lines.append(f"                       Matches SNI: {'Yes' if r.tls.certificate_matches_sni else 'No'}")
        lines.append(f"      HTTP Stage     : Status {r.http.status_code or 'N/A'} (Server: {r.http.server_header or 'N/A'})")
        lines.append("-----------------------------------------------------------------------")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return True
