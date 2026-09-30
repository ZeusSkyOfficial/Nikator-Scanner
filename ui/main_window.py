"""Main application window for Nikator Scanner.
Constructs top header with window controls, left sidebar navigation,
central stacked widget for modules, and real-time diagnostic status bar.
"""

from __future__ import annotations

import sys
from typing import Optional

from PySide6.QtCore import QPoint, QSize, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QMouseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSizeGrip,
    QSizePolicy,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from models.results import ApplicationSettings
from ui.compatibility_page import CompatibilityPage
from ui.config_page import ConfigPage
from ui.dialogs import AboutDialog
from ui.history_page import HistoryPage
from ui.icons import get_icon, get_pixmap
from ui.ip_page import IPTesterPage
from ui.scanner_page import ScannerPage
from ui.settings_page import SettingsPage
from ui.sidebar import Sidebar
from ui.theme import Colors, get_theme_stylesheet
from utils.settings import SettingsManager


class CustomTitleBar(QFrame):
    """Futuristic top header and window control bar."""

    def __init__(self, parent_window: QMainWindow) -> None:
        super().__init__(parent_window)
        self.parent_window = parent_window
        self._drag_pos = QPoint()
        self.setObjectName("TopHeader")
        self.setFixedHeight(54)
        self.setStyleSheet(f"""
            QFrame#TopHeader {{
                background-color: {Colors.DARK_SURFACE};
                border-bottom: 1px solid {Colors.DARK_BORDER};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        # Brand Logo & Title
        logo_lbl = QLabel()
        logo_lbl.setPixmap(get_pixmap("network", color=Colors.NEON_BLUE, size=24))
        layout.addWidget(logo_lbl)

        brand_layout = QVBoxLayout()
        brand_layout.setContentsMargins(0, 0, 0, 0)
        brand_layout.setSpacing(0)

        app_name = QLabel("Nikator Scanner")
        app_name.setStyleSheet("font-size: 15px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.5px;")

        app_sub = QLabel("SNI • DNS • TLS • سوئیت عیب‌یابی شبکه | تیم نیکاتور")
        app_sub.setStyleSheet(f"font-size: 10px; color: {Colors.NEON_BLUE}; font-weight: 600;")

        brand_layout.addWidget(app_name)
        brand_layout.addWidget(app_sub)
        layout.addLayout(brand_layout)

        layout.addStretch()

        # Telegram Creator Link Button
        self.tg_btn = QPushButton("تلگرام سازنده")
        self.tg_btn.setIcon(get_icon("globe", color=Colors.NEON_BLUE, size=14))
        self.tg_btn.setToolTip("ارتباط با سازنده در تلگرام: @Zeusskyofficial")
        self.tg_btn.setCursor(Qt.PointingHandCursor)
        self.tg_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(0, 212, 255, 0.12);
                color: #00d4ff;
                border: 1px solid rgba(0, 212, 255, 0.35);
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: rgba(0, 212, 255, 0.25);
                border: 1px solid #00d4ff;
            }}
        """)
        self.tg_btn.clicked.connect(self._open_telegram)
        layout.addWidget(self.tg_btn)

        # Settings Shortcut
        self.settings_btn = QPushButton()
        self.settings_btn.setFixedSize(32, 32)
        self.settings_btn.setIcon(get_icon("settings", color=Colors.DARK_TEXT_SECONDARY, size=16))
        self.settings_btn.setToolTip("تنظیمات برنامه")
        self.settings_btn.clicked.connect(lambda: self.parent_window.switch_page(5))
        layout.addWidget(self.settings_btn)

        # About Button
        self.about_btn = QPushButton()
        self.about_btn.setFixedSize(32, 32)
        self.about_btn.setIcon(get_icon("shield", color=Colors.DARK_TEXT_SECONDARY, size=16))
        self.about_btn.setToolTip("درباره Nikator Scanner (تیم نیکاتور)")
        self.about_btn.clicked.connect(self._show_about)
        layout.addWidget(self.about_btn)

        # Window Controls Divider
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color: {Colors.DARK_BORDER}; margin: 4px 2px;")
        layout.addWidget(sep)

        # Minimize
        min_btn = QPushButton("–")
        min_btn.setObjectName("WinMinBtn")
        min_btn.setFixedSize(32, 28)
        min_btn.setToolTip("کوچک کردن پنجره")
        min_btn.clicked.connect(self.parent_window.showMinimized)
        layout.addWidget(min_btn)

        # Maximize / Restore
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("WinMaxBtn")
        self.max_btn.setFixedSize(32, 28)
        self.max_btn.setToolTip("بزرگنمایی / بازگردانی")
        self.max_btn.clicked.connect(self._toggle_maximize)
        layout.addWidget(self.max_btn)

        # Close
        close_btn = QPushButton("✕")
        close_btn.setObjectName("WinCloseBtn")
        close_btn.setFixedSize(32, 28)
        close_btn.setToolTip("بستن برنامه")
        close_btn.clicked.connect(self.parent_window.close)
        layout.addWidget(close_btn)

    def _toggle_maximize(self) -> None:
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self.max_btn.setText("□")
        else:
            self.parent_window.showMaximized()
            self.max_btn.setText("❐")

    def _show_about(self) -> None:
        dlg = AboutDialog(self.parent_window)
        dlg.exec()

    def _open_telegram(self) -> None:
        import webbrowser
        webbrowser.open("https://t.me/Zeusskyofficial")

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.parent_window.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() == Qt.LeftButton and not self.parent_window.isMaximized():
            self.parent_window.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            self._toggle_maximize()


class MainWindow(QMainWindow):
    """Main application shell window for Nikator Scanner."""

    def __init__(self, settings: Optional[ApplicationSettings] = None) -> None:
        super().__init__()
        self.settings = settings or SettingsManager.get_instance().settings
        self.settings.theme_mode = "dark"
        self.is_dark = True

        self.setWindowTitle("نیکاتور اسکنر (Nikator Scanner) — سوئیت عیب‌یابی شبکه | تیم نیکاتور")
        self.setWindowIcon(get_icon("network", color=Colors.NEON_BLUE, size=32))
        self.setMinimumSize(1240, 720)
        self.resize(1400, 860)

        # Frameless window for bespoke dark futuristic styling
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)

        self._init_ui()
        self.apply_theme()

    def _init_ui(self) -> None:
        central_widget = QWidget()
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Custom Top Header Bar
        self.title_bar = CustomTitleBar(self)
        root_layout.addWidget(self.title_bar)

        # 2. Main Body: Sidebar + Stacked Widget
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Sidebar
        self.sidebar = Sidebar(self)
        self.sidebar.page_selected.connect(self.switch_page)
        body_layout.addWidget(self.sidebar)

        # Right Stacked Pages
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setObjectName("MainContentArea")

        # Page 0: SNI Scanner (Dashboard)
        self.scanner_page = ScannerPage(self.settings, self)
        self.scanner_page.status_updated.connect(self._on_scanner_status_updated)
        self.stacked_widget.addWidget(self.scanner_page)

        # Page 1: Configuration Tester
        self.config_page = ConfigPage(self.settings, self)
        self.stacked_widget.addWidget(self.config_page)

        # Page 2: IP Tester
        self.ip_page = IPTesterPage(self.settings, self)
        self.stacked_widget.addWidget(self.ip_page)

        # Page 3: SNI Compatibility
        self.compat_page = CompatibilityPage(self.settings, self)
        self.stacked_widget.addWidget(self.compat_page)

        # Page 4: History
        self.history_page = HistoryPage(self)
        self.stacked_widget.addWidget(self.history_page)

        # Page 5: Settings
        self.settings_page = SettingsPage(self.settings, self)
        self.settings_page.theme_toggled.connect(self._on_theme_toggled)
        self.settings_page.settings_applied.connect(self.apply_theme)
        self.stacked_widget.addWidget(self.settings_page)

        body_layout.addWidget(self.stacked_widget, stretch=1)
        root_layout.addWidget(body_widget, stretch=1)

        # 3. Bottom Status Bar
        self._init_status_bar(root_layout)

    def _init_status_bar(self, parent_layout: QVBoxLayout) -> None:
        status_frame = QFrame()
        status_frame.setObjectName("CustomStatusBar")
        status_frame.setFixedHeight(34)
        status_frame.setStyleSheet(f"""
            QFrame#CustomStatusBar {{
                background-color: {Colors.DARK_SURFACE};
                border-top: 1px solid {Colors.DARK_BORDER};
            }}
        """)

        sb_layout = QHBoxLayout(status_frame)
        sb_layout.setContentsMargins(14, 0, 14, 0)
        sb_layout.setSpacing(16)

        # Left State Indicator
        state_box = QHBoxLayout()
        state_box.setSpacing(6)
        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {Colors.SUCCESS_GREEN}; font-size: 14px;")
        self.status_state_lbl = QLabel("آماده")
        self.status_state_lbl.setStyleSheet(f"color: #FFFFFF; font-weight: 600; font-size: 11px;")
        state_box.addWidget(self.status_dot)
        state_box.addWidget(self.status_state_lbl)
        sb_layout.addLayout(state_box)

        # Center Current Operation
        self.status_op_lbl = QLabel("وضعیت: آماده")
        self.status_op_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        sb_layout.addWidget(self.status_op_lbl, stretch=1)

        # Diagnostic Stats
        self.status_tested_lbl = QLabel("تست‌شده: ۰ / ۰")
        self.status_tested_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        sb_layout.addWidget(self.status_tested_lbl)

        self.status_success_lbl = QLabel("موفق: ۰")
        self.status_success_lbl.setStyleSheet(f"color: {Colors.SUCCESS_GREEN}; font-weight: 600; font-size: 11px;")
        sb_layout.addWidget(self.status_success_lbl)

        self.status_failed_lbl = QLabel("ناموفق: ۰")
        self.status_failed_lbl.setStyleSheet(f"color: {Colors.FAILED_RED}; font-weight: 600; font-size: 11px;")
        sb_layout.addWidget(self.status_failed_lbl)

        self.status_latency_lbl = QLabel("پینگ: ۰ ms")
        self.status_latency_lbl.setStyleSheet(f"color: {Colors.WARNING_AMBER}; font-weight: 600; font-size: 11px;")
        sb_layout.addWidget(self.status_latency_lbl)

        # Team & Creator Label in Status Bar
        team_lbl = QLabel("تیم نیکاتور | سازنده: @Zeusskyofficial")
        team_lbl.setStyleSheet(f"color: {Colors.NEON_BLUE}; font-size: 11px; font-weight: 600;")
        team_lbl.setToolTip(
            "تمامی حقوق این برنامه برای تیم نیکاتور میباشد و هر گونه کپی برداری از ان دامن شما را خواهد گرفت و به خاک سیاه خواهد نشاند با تشکر تیم نیکاتور | تلگرام: @Zeusskyofficial"
        )
        sb_layout.addWidget(team_lbl)

        # Window Resizer Grip
        grip = QSizeGrip(self)
        grip.setFixedSize(14, 14)
        sb_layout.addWidget(grip)

        parent_layout.addWidget(status_frame)

    def switch_page(self, index: int) -> None:
        self.stacked_widget.setCurrentIndex(index)
        self.sidebar.set_current_index(index)
        if index == 4:
            self.history_page.refresh_sessions()

    def toggle_theme(self) -> None:
        # Enforce dark mode permanently as requested
        self.is_dark = True
        self.settings.theme_mode = "dark"
        self.apply_theme()

    def _on_theme_toggled(self, mode: str) -> None:
        self.is_dark = True
        self.settings.theme_mode = "dark"
        self.apply_theme()

    def apply_theme(self) -> None:
        qss = get_theme_stylesheet(is_dark=self.is_dark, font_size=self.settings.font_size)
        self.setStyleSheet(qss)

    def _on_scanner_status_updated(
        self,
        state: str,
        current_op: str,
        tested: int,
        total: int,
        success: int,
        avg_lat: float,
    ) -> None:
        if state == "running":
            self.status_dot.setStyleSheet(f"color: {Colors.WARNING_AMBER}; font-size: 14px;")
            self.status_state_lbl.setText("در حال اجرا")
        else:
            self.status_dot.setStyleSheet(f"color: {Colors.SUCCESS_GREEN}; font-size: 14px;")
            self.status_state_lbl.setText("آماده")

        self.status_op_lbl.setText(f"عملیات: {current_op}")
        self.status_tested_lbl.setText(f"تست‌شده: {tested} / {total}")
        self.status_success_lbl.setText(f"موفق: {success}")
        failed = max(0, tested - success)
        self.status_failed_lbl.setText(f"ناموفق: {failed}")
        self.status_latency_lbl.setText(f"پینگ: {avg_lat:.0f} ms")

    def _stop_active_scan(self) -> None:
        curr = self.stacked_widget.currentIndex()
        if curr == 0:
            self.scanner_page.stop_scan()
        elif curr == 1:
            self.config_page.stop_test()
        elif curr == 2:
            self.ip_page.stop_scan()
        elif curr == 3:
            self.compat_page.stop_research()
