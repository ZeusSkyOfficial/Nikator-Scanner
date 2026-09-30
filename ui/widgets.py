"""Reusable GUI widgets for Nikator Scanner.
Includes StatCard, CircularStatusIndicator, ToastNotification, and NetworkWaveWidget.
"""

from __future__ import annotations

import math
from typing import Optional

from PySide6.QtCore import QPoint, QPropertyAnimation, QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui.icons import get_icon, get_pixmap
from ui.theme import Colors


class CircularStatusIndicator(QWidget):
    """Compact circular indicator for table cells (Green Check, Red X, Amber, Gray)."""

    def __init__(
        self,
        state: str = "none",  # "success", "failed", "warning", "none"
        size: int = 18,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.state = state
        self._size = size
        self.setFixedSize(size, size)

    def set_state(self, state: str) -> None:
        self.state = state
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        r = min(w, h) - 2

        if self.state == "success":
            bg_color = QColor(Colors.SUCCESS_GREEN_BG)
            border_color = QColor(Colors.SUCCESS_GREEN)
            icon_char = "✓"
            text_color = QColor("#34D399")
        elif self.state == "failed":
            bg_color = QColor(Colors.FAILED_RED_BG)
            border_color = QColor(Colors.FAILED_RED)
            icon_char = "✕"
            text_color = QColor("#F87171")
        elif self.state == "warning" or self.state == "partial":
            bg_color = QColor(Colors.WARNING_AMBER_BG)
            border_color = QColor(Colors.WARNING_AMBER)
            icon_char = "!"
            text_color = QColor("#FBBF24")
        else:
            bg_color = QColor(Colors.DARK_SURFACE_ALT)
            border_color = QColor(Colors.DARK_BORDER_LIGHT)
            icon_char = "–"
            text_color = QColor(Colors.DARK_TEXT_MUTED)

        # Draw circle background
        painter.setBrush(QBrush(bg_color))
        painter.setPen(QPen(border_color, 1.2))
        painter.drawEllipse(1, 1, r, r)

        # Draw text symbol
        painter.setPen(text_color)
        font = painter.font()
        font.setPointSize(int(self._size * 0.48))
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRect(0, 0, w, h), Qt.AlignCenter, icon_char)
        painter.end()


class StatCard(QFrame):
    """High-contrast statistic card displaying real-time metrics with neon styling."""

    clicked = Signal()

    def __init__(
        self,
        icon_name: str,
        title: str,
        value: str = "0",
        subtitle: str = "",
        accent_color: str = Colors.NEON_BLUE,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setProperty("class", "CardFrame")
        self.accent_color = accent_color
        self.setCursor(Qt.PointingHandCursor)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(72)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        # Left Icon container
        self.icon_lbl = QLabel()
        self.icon_lbl.setPixmap(get_pixmap(icon_name, color=accent_color, size=22))
        self.icon_lbl.setFixedSize(28, 28)
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_lbl)

        # Middle Content layout
        text_layout = QVBoxLayout()
        text_layout.setSpacing(1)
        text_layout.setContentsMargins(0, 0, 0, 0)

        self.title_lbl = QLabel(title.upper())
        self.title_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px; font-weight: 600; letter-spacing: 0.3px;")

        self.value_lbl = QLabel(value)
        self.value_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_PRIMARY}; font-size: 17px; font-weight: 700;")

        self.sub_lbl = QLabel(subtitle)
        self.sub_lbl.setStyleSheet(f"color: {accent_color}; font-size: 10px; font-weight: 600;")
        if not subtitle:
            self.sub_lbl.hide()

        text_layout.addWidget(self.title_lbl)
        text_layout.addWidget(self.value_lbl)
        text_layout.addWidget(self.sub_lbl)
        layout.addLayout(text_layout)

        layout.addStretch()

        self.update_style()

    def update_style(self) -> None:
        self.setStyleSheet(f"""
            QFrame#StatCard {{
                background-color: {Colors.DARK_SURFACE};
                border: 1px solid {Colors.DARK_BORDER};
                border-left: 3px solid {self.accent_color};
                border-radius: 8px;
            }}
            QFrame#StatCard:hover {{
                background-color: {Colors.DARK_SURFACE_HOVER};
                border-color: {Colors.DARK_BORDER_LIGHT};
            }}
        """)

    def set_value(self, value: str, subtitle: Optional[str] = None) -> None:
        self.value_lbl.setText(value)
        if subtitle is not None:
            self.sub_lbl.setText(subtitle)
            self.sub_lbl.setVisible(bool(subtitle))

    def mousePressEvent(self, event) -> None:
        self.clicked.emit()
        super().mousePressEvent(event)


class ToastNotification(QFrame):
    """Notification class kept for API compatibility, but disabled visually as requested."""

    def __init__(self, message: str, parent: Optional[QWidget] = None, duration_ms: int = 2500) -> None:
        super().__init__(parent)
        # Completely suppressed per user request: floating popup with checkmark removed
        self.hide()
        self.deleteLater()


class NetworkWaveWidget(QWidget):
    """Subtle animated / stylized network-wave graphic for the sidebar footer."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(50)
        self._phase = 0.0

        # Gentle timer for subtle animation
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._step)
        self.timer.start(50)

    def _step(self) -> None:
        self._phase += 0.05
        if self._phase > 2 * math.pi:
            self._phase -= 2 * math.pi
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Wave line 1 (Cyan/Neon Blue)
        pen1 = QPen(QColor(Colors.NEON_BLUE), 1.5)
        painter.setPen(pen1)
        points1 = []
        for x in range(0, w, 4):
            y = h / 2 + math.sin(x * 0.04 + self._phase) * 8 + math.cos(x * 0.02) * 4
            points1.append(QPoint(x, int(y)))

        for i in range(len(points1) - 1):
            painter.drawLine(points1[i], points1[i + 1])

        # Wave line 2 (Deep Purple/Blue subtle)
        pen2 = QPen(QColor(Colors.DNS_PURPLE), 1.0)
        pen2.setStyle(Qt.DotLine)
        painter.setPen(pen2)
        points2 = []
        for x in range(0, w, 4):
            y = h / 2 + math.sin(x * 0.05 - self._phase * 0.8) * 10
            points2.append(QPoint(x, int(y)))

        for i in range(len(points2) - 1):
            painter.drawLine(points2[i], points2[i + 1])

        painter.end()
