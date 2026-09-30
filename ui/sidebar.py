"""Vertical navigation sidebar for Nikator Scanner.
Houses module navigation cards, active item highlights, and footer branding.
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import NetworkWaveWidget


class NavItemWidget(QFrame):
    """Interactive navigation item with title, subtitle, and dynamic highlight state."""

    clicked = Signal(int)

    def __init__(
        self,
        index: int,
        icon_name: str,
        title: str,
        subtitle: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.index = index
        self.icon_name = icon_name
        self.is_active = False
        self.setCursor(Qt.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(56)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)

        # Icon
        self.icon_lbl = QLabel()
        self.icon_lbl.setFixedSize(22, 22)
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.icon_lbl)

        # Titles
        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_PRIMARY}; font-size: 13px; font-weight: 600;")

        self.subtitle_lbl = QLabel(subtitle)
        self.subtitle_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 10px;")

        text_layout.addWidget(self.title_lbl)
        text_layout.addWidget(self.subtitle_lbl)
        layout.addLayout(text_layout)

        layout.addStretch()

        self.set_active(False)

    def set_active(self, active: bool) -> None:
        self.is_active = active
        if active:
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: #1E3A8A;
                    border: 1px solid {Colors.PRIMARY_BLUE};
                    border-left: 4px solid {Colors.NEON_BLUE};
                    border-radius: 8px;
                }}
            """)
            self.icon_lbl.setPixmap(get_pixmap(self.icon_name, color=Colors.NEON_BLUE, size=20))
            self.title_lbl.setStyleSheet(f"color: #FFFFFF; font-size: 13px; font-weight: 700;")
            self.subtitle_lbl.setStyleSheet(f"color: {Colors.NEON_BLUE}; font-size: 10px; font-weight: 500;")
        else:
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: transparent;
                    border: 1px solid transparent;
                    border-radius: 8px;
                }}
                QFrame:hover {{
                    background-color: {Colors.DARK_SURFACE_HOVER};
                    border: 1px solid {Colors.DARK_BORDER};
                }}
            """)
            self.icon_lbl.setPixmap(get_pixmap(self.icon_name, color=Colors.DARK_TEXT_SECONDARY, size=20))
            self.title_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_PRIMARY}; font-size: 13px; font-weight: 600;")
            self.subtitle_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 10px;")

    def mousePressEvent(self, event) -> None:
        self.clicked.emit(self.index)
        super().mousePressEvent(event)


class Sidebar(QFrame):
    """Vertical sidebar housing application modules and brand intelligence panel."""

    page_selected = Signal(int)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("SidebarFrame")
        self.setFixedWidth(248)

        self.items: List[NavItemWidget] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 16, 10, 16)
        layout.setSpacing(6)

        # Navigation Items definitions
        nav_data = [
            ("globe", "اسکنر SNI", "شناسایی ساب‌دامین و SNI"),
            ("config", "تست‌کننده کانفیگ", "بررسی کانفیگ‌های شبکه"),
            ("ip", "تست‌کننده آی‌پی", "بررسی سلامت لیست IP"),
            ("compat", "سازگاری SNI", "پژوهش رفتار و تطابق SNI"),
            ("history", "تاریخچه اسکن", "نتایج و نشست‌های پیشین"),
            ("settings", "تنظیمات برنامه", "پیکربندی شبکه و ظاهر"),
        ]

        for idx, (icon_name, title, subtitle) in enumerate(nav_data):
            item = NavItemWidget(idx, icon_name, title, subtitle, self)
            item.clicked.connect(self._on_item_clicked)
            self.items.append(item)
            layout.addWidget(item)

        layout.addStretch()

        # Footer Branding & Wave Art
        footer_frame = QFrame()
        footer_frame.setObjectName("SidebarFooter")
        footer_frame.setStyleSheet(f"""
            QFrame#SidebarFooter {{
                background-color: {Colors.DARK_SURFACE_ALT};
                border: 1px solid rgba(0, 212, 255, 0.25);
                border-radius: 8px;
                padding: 4px;
            }}
        """)
        footer_layout = QVBoxLayout(footer_frame)
        footer_layout.setContentsMargins(10, 8, 10, 8)
        footer_layout.setSpacing(4)

        wave = NetworkWaveWidget(self)
        footer_layout.addWidget(wave)

        intel_title = QLabel("تیم نیکاتور | Nikator Team")
        intel_title.setStyleSheet(f"color: {Colors.NEON_BLUE}; font-size: 11px; font-weight: 800;")
        footer_layout.addWidget(intel_title)

        rights_lbl = QLabel(
            "تمامی حقوق این برنامه برای تیم نیکاتور میباشد و هر گونه کپی برداری از ان دامن شما را خواهد گرفت و به خاک سیاه خواهد نشاند با تشکر تیم نیکاتور"
        )
        rights_lbl.setStyleSheet("color: #E2E8F0; font-size: 9.5px; font-weight: 600; line-height: 1.4;")
        rights_lbl.setWordWrap(True)
        footer_layout.addWidget(rights_lbl)

        tg_link_btn = QPushButton("سازنده: @Zeusskyofficial")
        tg_link_btn.setIcon(get_icon("globe", color=Colors.NEON_BLUE, size=12))
        tg_link_btn.setCursor(Qt.PointingHandCursor)
        tg_link_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 212, 255, 0.1);
                color: #38BDF8;
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 4px;
                padding: 3px 6px;
                font-size: 10px;
                font-weight: bold;
                text-align: right;
            }
            QPushButton:hover {
                background-color: rgba(0, 212, 255, 0.22);
                border: 1px solid #00d4ff;
                color: #FFFFFF;
            }
        """)
        tg_link_btn.clicked.connect(self._open_telegram)
        footer_layout.addWidget(tg_link_btn)

        layout.addWidget(footer_frame)

        # Set default active item (SNI Scanner)
        self.set_current_index(0)

    def _on_item_clicked(self, index: int) -> None:
        self.set_current_index(index)
        self.page_selected.emit(index)

    def set_current_index(self, index: int) -> None:
        for idx, item in enumerate(self.items):
            item.set_active(idx == index)

    def _open_telegram(self) -> None:
        import webbrowser
        webbrowser.open("https://t.me/Zeusskyofficial")
