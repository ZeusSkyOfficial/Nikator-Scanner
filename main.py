"""Nikator Scanner — Advanced SNI / DNS / TLS / Network Diagnostic Suite.

Entry point for launching the desktop application.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

# Ensure current directory is on python path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from ui.icons import get_icon
from ui.main_window import MainWindow
from ui.theme import Colors
from utils.logging_conf import setup_logging
from utils.settings import SettingsManager


def main() -> None:
    """Initialize and run Nikator Scanner application."""
    # 1. Load application preferences
    settings_mgr = SettingsManager.get_instance()
    settings = settings_mgr.settings

    # 2. Setup logging
    logger = setup_logging(level=settings.log_level, enable=settings.enable_logging)
    logger.info("Initializing Nikator Scanner Diagnostic Suite (Nikator Team)...")

    # 3. High-DPI attributes (Qt6 handles scaling automatically, customize rounding)
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    except Exception:
        pass

    # 4. Instantiate QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Nikator Scanner")
    app.setApplicationDisplayName("Nikator Scanner")
    app.setOrganizationName("Nikator Team")

    # Set default clean system font
    font = QFont("Segoe UI", settings.font_size)
    font.setStyleHint(QFont.SansSerif)
    app.setFont(font)

    # Set application icon
    app_icon = get_icon("network", color=Colors.NEON_BLUE, size=32)
    if app_icon:
        app.setWindowIcon(app_icon)

    # 5. Create and present main window
    window = MainWindow(settings)
    window.show()

    logger.info("Nikator Scanner main window presented successfully.")

    # 6. Execute Qt event loop
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
