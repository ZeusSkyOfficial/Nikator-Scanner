"""Clipboard utilities for Nikator Scanner.
Provides seamless one-click copying with GUI clipboard access and OS fallbacks.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Optional

try:
    from PySide6.QtGui import QGuiApplication
    HAS_QT = True
except ImportError:
    HAS_QT = False


def copy_text_to_clipboard(text: str) -> bool:
    """Copy given text string to the system clipboard."""
    if not text:
        return False

    if HAS_QT:
        app = QGuiApplication.instance()
        if app:
            clipboard = QGuiApplication.clipboard()
            if clipboard:
                clipboard.setText(text)
                return True

    # Windows fallback via clip.exe
    if sys.platform == "win32":
        try:
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE, shell=True)
            p.communicate(input=text.encode("utf-8"))
            return True
        except Exception:
            pass

    return False
