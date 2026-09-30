"""Safe configuration parser for Nikator Scanner.
Parses network configurations (URIs, JSON, YAML-like key-value, raw endpoints)
without executing any code, extracting endpoints, ports, SNIs, and TLS settings.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse
from utils.validation import extract_host_port, is_valid_port


@dataclass
class ParsedEndpoint:
    """Represents an extracted diagnostic endpoint from a configuration."""
    raw_entry: str
    hostname: str
    port: int = 443
    sni: str = ""
    protocol: str = "tcp"
    use_tls: bool = True
    alpn: str = ""
    remarks: str = ""
    clean_ip: str = ""
    full_config: str = ""

    def generate_config_with_ip(self, new_ip: str) -> str:
        """Substitute the connection IP/address in the config with a verified clean IP."""
        raw = (self.full_config or self.raw_entry or "").strip()
        if not raw or not new_ip:
            return f"{new_ip}:{self.port}"

        # 1. URI Schemes (vless://, trojan://, ss://, https://, etc.)
        if "://" in raw and not raw.startswith("vmess://"):
            try:
                parsed = urlparse(raw)
                netloc = parsed.netloc
                if "@" in netloc:
                    userinfo, _ = netloc.split("@", 1)
                    new_netloc = f"{userinfo}@{new_ip}:{self.port}"
                else:
                    new_netloc = f"{new_ip}:{self.port}"

                query_dict = parse_qs(parsed.query)
                # Keep original domain in sni and host if not already set
                if self.hostname and not self._is_ip(self.hostname):
                    if "sni" not in query_dict:
                        query_dict["sni"] = [self.sni or self.hostname]
                    if "host" not in query_dict:
                        query_dict["host"] = [self.hostname]

                new_query = urlencode(query_dict, doseq=True)
                orig_frag = unquote(parsed.fragment) if parsed.fragment else ""
                new_frag = f"{orig_frag}-{new_ip}" if orig_frag else f"Clean-{new_ip}"

                return urlunparse((
                    parsed.scheme,
                    new_netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    quote(new_frag),
                ))
            except Exception:
                pass

        # 2. VMess (base64 JSON)
        if raw.startswith("vmess://"):
            try:
                b64 = raw[8:].strip()
                b64 += "=" * ((4 - len(b64) % 4) % 4)
                decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                data = json.loads(decoded)

                orig_add = str(data.get("add", "")).strip()
                if orig_add and not self._is_ip(orig_add):
                    if not data.get("host"):
                        data["host"] = orig_add
                    if not data.get("sni"):
                        data["sni"] = orig_add

                data["add"] = new_ip
                orig_ps = str(data.get("ps", ""))
                data["ps"] = f"{orig_ps}-{new_ip}" if orig_ps else f"Clean-{new_ip}"

                new_json = json.dumps(data, ensure_ascii=False)
                new_b64 = base64.b64encode(new_json.encode("utf-8")).decode("utf-8")
                return f"vmess://{new_b64}"
            except Exception:
                pass

        # 3. Simple host:port
        return f"{new_ip}:{self.port}"

    @staticmethod
    def _is_ip(val: str) -> bool:
        parts = val.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class SafeConfigParser:
    """Extracts endpoint connection targets from varied network configuration formats."""

    @classmethod
    def parse(cls, content: str) -> List[ParsedEndpoint]:
        """Parse configuration text safely and return list of unique ParsedEndpoints."""
        text = content.strip()
        if not text:
            return []

        endpoints: List[ParsedEndpoint] = []
        seen = set()

        def add_endpoint(ep: ParsedEndpoint) -> None:
            if not ep.hostname:
                return
            key = (ep.hostname.lower(), ep.port, (ep.sni or ep.hostname).lower())
            if key not in seen:
                seen.add(key)
                if not ep.sni:
                    ep.sni = ep.hostname
                endpoints.append(ep)

        # 1. Try parsing as JSON
        if (text.startswith("{") and text.endswith("}")) or (text.startswith("[") and text.endswith("]")):
            try:
                data = json.loads(text)
                json_endpoints = cls._parse_json_structure(data)
                for ep in json_endpoints:
                    add_endpoint(ep)
                if endpoints:
                    return endpoints
            except Exception:
                pass

        # 2. Process line by line
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]

        for line in lines:
            # Check for URI schemes
            if "://" in line:
                ep = cls._parse_uri(line)
                if ep:
                    add_endpoint(ep)
                    continue

            # Check for vmess:// base64
            if line.startswith("vmess://"):
                ep = cls._parse_vmess(line)
                if ep:
                    add_endpoint(ep)
                    continue

            # Check for key-value pair like 'server: port' or 'server,port'
            if ":" in line or "," in line:
                ep = cls._parse_line_endpoint(line)
                if ep:
                    add_endpoint(ep)
                    continue

            # Raw host/IP alone
            if line:
                host, port = extract_host_port(line, default_port=443)
                if host:
                    add_endpoint(
                        ParsedEndpoint(
                            raw_entry=line,
                            hostname=host,
                            port=port,
                            sni=host,
                            protocol="tcp",
                            use_tls=port in (443, 8443),
                        )
                    )

        return endpoints

    @classmethod
    def _parse_uri(cls, uri_str: str) -> Optional[ParsedEndpoint]:
        """Parse standard or proxy URIs (vless, trojan, ss, https, http)."""
        try:
            parsed = urlparse(uri_str)
            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""
            port = parsed.port or (80 if scheme == "http" else 443)
            remarks = unquote(parsed.fragment) if parsed.fragment else ""

            # Parse query parameters
            query_params = parse_qs(parsed.query)
            sni = query_params.get("sni", [""])[0] or query_params.get("peer", [""])[0] or hostname
            security = query_params.get("security", [""])[0].lower()
            use_tls = security in ("tls", "reality") or scheme in ("https", "trojan") or port in (443, 8443)
            alpn = query_params.get("alpn", [""])[0]

            if hostname:
                return ParsedEndpoint(
                    raw_entry=uri_str,
                    full_config=uri_str,
                    hostname=hostname,
                    port=port,
                    sni=sni or hostname,
                    protocol=scheme,
                    use_tls=use_tls,
                    alpn=alpn,
                    remarks=remarks,
                )
        except Exception:
            pass
        return None

    @classmethod
    def _parse_vmess(cls, vmess_str: str) -> Optional[ParsedEndpoint]:
        """Safely decode base64 encoded vmess config without execution."""
        try:
            raw_b64 = vmess_str[8:].strip()
            # Fix padding
            raw_b64 += "=" * ((4 - len(raw_b64) % 4) % 4)
            decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
            data = json.loads(decoded)

            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 443))
            sni = str(data.get("sni", "")).strip() or str(data.get("host", "")).strip() or host
            tls_val = str(data.get("tls", "")).lower()
            use_tls = tls_val == "tls" or port in (443, 8443)
            remarks = str(data.get("ps", ""))

            if host:
                return ParsedEndpoint(
                    raw_entry=vmess_str,
                    full_config=vmess_str,
                    hostname=host,
                    port=port,
                    sni=sni,
                    protocol="vmess",
                    use_tls=use_tls,
                    alpn=str(data.get("alpn", "")),
                    remarks=remarks,
                )
        except Exception:
            pass
        return None

    @classmethod
    def _parse_json_structure(cls, data: Any) -> List[ParsedEndpoint]:
        """Inspect JSON dict or list for outbound / server configurations."""
        endpoints: List[ParsedEndpoint] = []

        if isinstance(data, list):
            for item in data:
                endpoints.extend(cls._parse_json_structure(item))
            return endpoints

        if isinstance(data, dict):
            # Check for outbounds list
            if "outbounds" in data and isinstance(data["outbounds"], list):
                for ob in data["outbounds"]:
                    endpoints.extend(cls._parse_json_structure(ob))

            # Check proxies list (Clash format)
            if "proxies" in data and isinstance(data["proxies"], list):
                for proxy in data["proxies"]:
                    if isinstance(proxy, dict):
                        server = proxy.get("server")
                        port = proxy.get("port", 443)
                        sni = proxy.get("sni") or proxy.get("servername") or server
                        tls_flag = proxy.get("tls", True)
                        if server:
                            endpoints.append(
                                ParsedEndpoint(
                                    raw_entry=f"Clash: {proxy.get('name', server)}",
                                    hostname=str(server),
                                    port=int(port) if is_valid_port(port) else 443,
                                    sni=str(sni) if sni else str(server),
                                    protocol=str(proxy.get("type", "tcp")),
                                    use_tls=bool(tls_flag),
                                    remarks=str(proxy.get("name", "")),
                                )
                            )

            # Direct server/address fields
            server = data.get("server") or data.get("address") or data.get("host")
            if server and isinstance(server, str):
                port = data.get("port", 443)
                sni = data.get("sni") or data.get("server_name") or server
                tls_val = data.get("tls", True)
                endpoints.append(
                    ParsedEndpoint(
                        raw_entry=f"JSON: {server}",
                        hostname=server,
                        port=int(port) if is_valid_port(port) else 443,
                        sni=str(sni) if sni else server,
                        protocol=str(data.get("protocol", "tcp")),
                        use_tls=bool(tls_val),
                    )
                )

        return endpoints

    @classmethod
    def _parse_line_endpoint(cls, line: str) -> Optional[ParsedEndpoint]:
        """Parse 'host:port' or 'host,port,sni' lines."""
        try:
            if "," in line:
                parts = [p.strip() for p in line.split(",")]
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 443
                sni = parts[2] if len(parts) > 2 else host
                return ParsedEndpoint(
                    raw_entry=line,
                    hostname=host,
                    port=port,
                    sni=sni,
                    protocol="tcp",
                    use_tls=port in (443, 8443),
                )
            if ":" in line:
                host, port = extract_host_port(line, default_port=443)
                if host:
                    return ParsedEndpoint(
                        raw_entry=line,
                        hostname=host,
                        port=port,
                        sni=host,
                        protocol="tcp",
                        use_tls=port in (443, 8443),
                    )
        except Exception:
            pass
        return None
