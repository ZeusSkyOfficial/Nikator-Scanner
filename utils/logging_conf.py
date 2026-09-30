"""Logging configuration for Nikator Scanner.
Provides structured file and console logging with log rotation and path helpers.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path


def get_log_dir() -> Path:
    """Return the application log directory path."""
    log_dir = Path.home() / ".nikator_scanner" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logging(level: str = "INFO", enable: bool = True) -> logging.Logger:
    """Configure root and application loggers."""
    logger = logging.getLogger("NikatorScanner")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    if not enable:
        logger.addHandler(logging.NullHandler())
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(module)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Rotating File Handler (up to 5MB, 3 backups)
    log_file = get_log_dir() / "nikator_scanner.log"
    try:
        file_handler = RotatingFileHandler(
            str(log_file), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning(f"Could not initialize file logging: {e}")

    return logger
