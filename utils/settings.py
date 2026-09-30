"""Settings manager for Nikator Scanner.
Loads, validates, and persists user preferences in a JSON configuration file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict
from models.results import ApplicationSettings


def get_default_config_path() -> Path:
    """Determine cross-platform configuration file path."""
    app_dir = Path.home() / ".nikator_scanner"
    old_dir = Path.home() / ".netscanner_pro"
    app_dir.mkdir(parents=True, exist_ok=True)
    cfg_file = app_dir / "config.json"
    old_cfg = old_dir / "config.json"
    if not cfg_file.exists() and old_cfg.exists():
        try:
            import shutil
            shutil.copy2(old_cfg, cfg_file)
        except Exception:
            pass
    return cfg_file


class SettingsManager:
    """Manages loading and saving application configuration settings."""

    _instance: Optional[SettingsManager] = None

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self.config_path = config_path or get_default_config_path()
        self.settings: ApplicationSettings = ApplicationSettings()
        self.load()

    @classmethod
    def get_instance(cls) -> SettingsManager:
        if cls._instance is None:
            cls._instance = SettingsManager()
        return cls._instance

    def load(self) -> ApplicationSettings:
        """Load settings from JSON file or fall back to defaults."""
        if not self.config_path.exists():
            self.settings = ApplicationSettings()
            self.save()
            return self.settings

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data: Dict[str, Any] = json.load(f)

            self.settings = ApplicationSettings(
                dns_timeout=float(data.get("dns_timeout", 3.0)),
                tcp_timeout=float(data.get("tcp_timeout", 3.0)),
                tls_timeout=float(data.get("tls_timeout", 4.0)),
                http_timeout=float(data.get("http_timeout", 4.0)),
                custom_dns_servers=list(data.get("custom_dns_servers", ["1.1.1.1", "8.8.8.8"])),
                max_concurrency=int(data.get("max_concurrency", 25)),
                retry_count=int(data.get("retry_count", 1)),
                rate_limit_delay_ms=int(data.get("rate_limit_delay_ms", 0)),
                theme_mode=str(data.get("theme_mode", "dark")),
                compact_table=bool(data.get("compact_table", False)),
                font_size=int(data.get("font_size", 12)),
                enable_logging=bool(data.get("enable_logging", True)),
                log_level=str(data.get("log_level", "INFO")),
                history_retention_days=int(data.get("history_retention_days", 30)),
                user_wordlist_path=str(data.get("user_wordlist_path", "")),
                export_directory=str(data.get("export_directory", "")),
            )
        except Exception:
            self.settings = ApplicationSettings()
        return self.settings

    def save(self) -> bool:
        """Persist current settings to disk."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "dns_timeout": self.settings.dns_timeout,
                "tcp_timeout": self.settings.tcp_timeout,
                "tls_timeout": self.settings.tls_timeout,
                "http_timeout": self.settings.http_timeout,
                "custom_dns_servers": self.settings.custom_dns_servers,
                "max_concurrency": self.settings.max_concurrency,
                "retry_count": self.settings.retry_count,
                "rate_limit_delay_ms": self.settings.rate_limit_delay_ms,
                "theme_mode": self.settings.theme_mode,
                "compact_table": self.settings.compact_table,
                "font_size": self.settings.font_size,
                "enable_logging": self.settings.enable_logging,
                "log_level": self.settings.log_level,
                "history_retention_days": self.settings.history_retention_days,
                "user_wordlist_path": self.settings.user_wordlist_path,
                "export_directory": self.settings.export_directory,
            }
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False
