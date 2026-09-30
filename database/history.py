"""SQLite database manager for persisting and querying scan history sessions.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
from models.results import (
    ScanSession,
    ScanResult,
    ScanTarget,
    DNSResult,
    TCPResult,
    TLSResult,
    HTTPResult,
    CertificateInfo,
    ScanStatus,
)


def get_default_db_path() -> Path:
    """Return default SQLite database path."""
    app_dir = Path.home() / ".nikator_scanner"
    old_dir = Path.home() / ".netscanner_pro"
    app_dir.mkdir(parents=True, exist_ok=True)
    db_file = app_dir / "history.db"
    old_db = old_dir / "history.db"
    if not db_file.exists() and old_db.exists():
        try:
            import shutil
            shutil.copy2(old_db, db_file)
        except Exception:
            pass
    return db_file


class HistoryManager:
    """Handles storage, retrieval, and management of historical diagnostic runs."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or get_default_db_path()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create required tables and indexes if they do not already exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target_domain TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    total_tested INTEGER DEFAULT 0,
                    successful_count INTEGER DEFAULT 0,
                    failed_count INTEGER DEFAULT 0,
                    avg_latency_ms REAL DEFAULT 0.0,
                    notes TEXT DEFAULT ''
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    result_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    ip TEXT,
                    port INTEGER,
                    sni TEXT,
                    status TEXT,
                    latency_ms REAL,
                    dns_resolved INTEGER,
                    tcp_connected INTEGER,
                    tls_success INTEGER,
                    http_status INTEGER,
                    cert_subject TEXT,
                    cert_issuer TEXT,
                    cert_valid_until TEXT,
                    raw_json TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id)")
            conn.commit()

    def save_session(self, session: ScanSession, results: List[ScanResult]) -> bool:
        """Store a completed or partial scan session and its results."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO sessions (
                        session_id, scan_type, target_domain, started_at, completed_at,
                        total_tested, successful_count, failed_count, avg_latency_ms, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session.session_id,
                    session.scan_type,
                    session.target_domain,
                    session.started_at,
                    session.completed_at,
                    session.total_tested,
                    session.successful_count,
                    session.failed_count,
                    session.avg_latency_ms,
                    ""
                ))

                for r in results:
                    raw_data = json.dumps({
                        "dns": {
                            "resolved": r.dns.resolved,
                            "ipv4": r.dns.ipv4_addresses,
                            "ipv6": r.dns.ipv6_addresses,
                            "cnames": r.dns.cnames,
                            "latency_ms": r.dns.latency_ms,
                            "error": r.dns.error,
                        },
                        "tcp": {
                            "connected": r.tcp.connected,
                            "remote_ip": r.tcp.remote_ip,
                            "port": r.tcp.port,
                            "latency_ms": r.tcp.latency_ms,
                            "error": r.tcp.error,
                        },
                        "tls": {
                            "handshake_success": r.tls.handshake_success,
                            "tls_version": r.tls.tls_version,
                            "cipher": r.tls.cipher,
                            "sni_used": r.tls.sni_used,
                            "latency_ms": r.tls.latency_ms,
                            "cert_matches_sni": r.tls.certificate_matches_sni,
                            "certificate": {
                                "subject": r.tls.certificate.subject,
                                "issuer": r.tls.certificate.issuer,
                                "sans": r.tls.certificate.subject_alt_names,
                                "valid_from": r.tls.certificate.valid_from,
                                "valid_until": r.tls.certificate.valid_until,
                                "is_valid": r.tls.certificate.is_valid,
                            },
                            "error": r.tls.error,
                        },
                        "http": {
                            "reachable": r.http.reachable,
                            "status_code": r.http.status_code,
                            "server": r.http.server_header,
                            "content_type": r.http.content_type,
                            "redirect_url": r.http.redirect_url,
                            "latency_ms": r.http.latency_ms,
                            "error": r.http.error,
                        },
                    })

                    cursor.execute("""
                        INSERT OR REPLACE INTO results (
                            result_id, session_id, hostname, ip, port, sni, status,
                            latency_ms, dns_resolved, tcp_connected, tls_success,
                            http_status, cert_subject, cert_issuer, cert_valid_until,
                            raw_json, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        r.id,
                        session.session_id,
                        r.target.hostname,
                        r.display_ip,
                        r.target.port,
                        r.target.sni,
                        r.status.value,
                        r.total_latency_ms,
                        1 if r.dns.resolved else 0,
                        1 if r.tcp.connected else 0,
                        1 if r.tls.handshake_success else 0,
                        r.http.status_code,
                        r.tls.certificate.subject,
                        r.tls.certificate.issuer,
                        r.tls.certificate.valid_until,
                        raw_data,
                        r.timestamp,
                    ))

                conn.commit()
            return True
        except Exception:
            return False

    def get_sessions(self, search: str = "", limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve list of scan sessions matching query."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if search.strip():
                query = "%" + search.strip() + "%"
                cursor.execute("""
                    SELECT * FROM sessions
                    WHERE target_domain LIKE ? OR scan_type LIKE ?
                    ORDER BY started_at DESC
                    LIMIT ? OFFSET ?
                """, (query, query, limit, offset))
            else:
                cursor.execute("""
                    SELECT * FROM sessions
                    ORDER BY started_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_session_results(self, session_id: str) -> List[ScanResult]:
        """Fetch all individual scan results for a specific session."""
        results: List[ScanResult] = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM results WHERE session_id = ? ORDER BY hostname ASC
            """, (session_id,))
            rows = cursor.fetchall()

            for row in rows:
                target = ScanTarget(
                    hostname=row["hostname"],
                    ip=row["ip"],
                    port=row["port"] or 443,
                    sni=row["sni"],
                )
                r = ScanResult(
                    id=row["result_id"],
                    target=target,
                    total_latency_ms=row["latency_ms"] or 0.0,
                    status=ScanStatus(row["status"]) if row["status"] in [s.value for s in ScanStatus] else ScanStatus.FAILED,
                    timestamp=row["timestamp"],
                )

                # Reconstruct granular stages from raw_json
                if row["raw_json"]:
                    try:
                        raw = json.loads(row["raw_json"])
                        d = raw.get("dns", {})
                        r.dns = DNSResult(
                            resolved=bool(d.get("resolved", False)),
                            ipv4_addresses=d.get("ipv4", []),
                            ipv6_addresses=d.get("ipv6", []),
                            cnames=d.get("cnames", []),
                            latency_ms=float(d.get("latency_ms", 0.0)),
                            error=d.get("error"),
                        )

                        t = raw.get("tcp", {})
                        r.tcp = TCPResult(
                            connected=bool(t.get("connected", False)),
                            remote_ip=str(t.get("remote_ip", "")),
                            port=int(t.get("port", 443)),
                            latency_ms=float(t.get("latency_ms", 0.0)),
                            error=t.get("error"),
                        )

                        tl = raw.get("tls", {})
                        c = tl.get("certificate", {})
                        cert = CertificateInfo(
                            subject=str(c.get("subject", "")),
                            issuer=str(c.get("issuer", "")),
                            subject_alt_names=list(c.get("sans", [])),
                            valid_from=str(c.get("valid_from", "")),
                            valid_until=str(c.get("valid_until", "")),
                            is_valid=bool(c.get("is_valid", False)),
                        )
                        r.tls = TLSResult(
                            handshake_success=bool(tl.get("handshake_success", False)),
                            tls_version=str(tl.get("tls_version", "")),
                            cipher=str(tl.get("cipher", "")),
                            sni_used=str(tl.get("sni_used", "")),
                            latency_ms=float(tl.get("latency_ms", 0.0)),
                            certificate_matches_sni=bool(tl.get("cert_matches_sni", False)),
                            certificate=cert,
                            error=tl.get("error"),
                        )

                        h = raw.get("http", {})
                        r.http = HTTPResult(
                            reachable=bool(h.get("reachable", False)),
                            status_code=int(h.get("status_code", 0)),
                            server_header=str(h.get("server", "")),
                            content_type=str(h.get("content_type", "")),
                            redirect_url=str(h.get("redirect_url", "")),
                            latency_ms=float(h.get("latency_ms", 0.0)),
                            error=h.get("error"),
                        )
                    except Exception:
                        pass
                results.append(r)
        return results

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its associated results."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM results WHERE session_id = ?", (session_id,))
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                conn.commit()
            return True
        except Exception:
            return False

    def clear_all(self) -> bool:
        """Purge all sessions and results."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM results")
                cursor.execute("DELETE FROM sessions")
                conn.commit()
            return True
        except Exception:
            return False
