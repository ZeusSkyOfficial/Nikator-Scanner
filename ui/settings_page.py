"""Settings page for Nikator Scanner.
Configures network timeouts, performance workers, theme appearance, logging, and data storage.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from models.results import ApplicationSettings
from ui.icons import get_icon
from ui.theme import Colors
from ui.widgets import ToastNotification
from utils.logging_conf import get_log_dir
from utils.settings import SettingsManager


class SettingsPage(QWidget):
    """Application preferences and configuration settings view."""

    settings_applied = Signal()
    theme_toggled = Signal(str)  # "dark" or "light"

    def __init__(self, settings: ApplicationSettings, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.settings_mgr = SettingsManager.get_instance()

        self._init_ui()
        self._load_settings_into_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(14)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        title_lbl = QLabel("تنظیمات برنامه")
        title_lbl.setStyleSheet("font-size: 22px; font-weight: 800; color: #FFFFFF;")
        sub_lbl = QLabel("تنظیم دقیق پارامترها و تایم‌اوت‌های شبکه، همزمانی موتور، ظاهر و لاگ‌های سیستم")
        sub_lbl.setStyleSheet(f"font-size: 13px; color: {Colors.DARK_TEXT_SECONDARY};")
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(sub_lbl)
        main_layout.addLayout(header_layout)

        # Scroll Area for clean scrolling on smaller screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        c_layout = QVBoxLayout(content)
        c_layout.setContentsMargins(0, 0, 10, 0)
        c_layout.setSpacing(16)

        # Section 1: Network Timeouts
        net_box, net_grid = self._create_card_section("عیب‌یابی شبکه و تایم‌اوت‌ها")

        net_grid.addWidget(QLabel("تایم‌اوت تفکیک DNS (ثانیه):"), 0, 0)
        self.dns_timeout_spin = QDoubleSpinBox()
        self.dns_timeout_spin.setRange(0.5, 30.0)
        self.dns_timeout_spin.setSingleStep(0.5)
        net_grid.addWidget(self.dns_timeout_spin, 0, 1)

        net_grid.addWidget(QLabel("تایم‌اوت اتصال TCP (ثانیه):"), 1, 0)
        self.tcp_timeout_spin = QDoubleSpinBox()
        self.tcp_timeout_spin.setRange(0.5, 30.0)
        self.tcp_timeout_spin.setSingleStep(0.5)
        net_grid.addWidget(self.tcp_timeout_spin, 1, 1)

        net_grid.addWidget(QLabel("تایم‌اوت هندشیک TLS (ثانیه):"), 2, 0)
        self.tls_timeout_spin = QDoubleSpinBox()
        self.tls_timeout_spin.setRange(0.5, 30.0)
        self.tls_timeout_spin.setSingleStep(0.5)
        net_grid.addWidget(self.tls_timeout_spin, 2, 1)

        net_grid.addWidget(QLabel("تایم‌اوت بررسی HTTP/HTTPS (ثانیه):"), 3, 0)
        self.http_timeout_spin = QDoubleSpinBox()
        self.http_timeout_spin.setRange(0.5, 30.0)
        self.http_timeout_spin.setSingleStep(0.5)
        net_grid.addWidget(self.http_timeout_spin, 3, 1)

        net_grid.addWidget(QLabel("سرورهای DNS سفارشی (جداشده با کاما):"), 4, 0)
        self.dns_servers_input = QLineEdit()
        self.dns_servers_input.setPlaceholderText("1.1.1.1, 8.8.8.8, 9.9.9.9")
        net_grid.addWidget(self.dns_servers_input, 4, 1)

        c_layout.addWidget(net_box)

        # Section 2: Performance & Concurrency
        perf_box, perf_grid = self._create_card_section("عملکرد موتور و همزمانی")

        perf_grid.addWidget(QLabel("حداکثر رشته‌های همزمان (Worker Threads):"), 0, 0)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 100)
        perf_grid.addWidget(self.concurrency_spin, 0, 1)

        perf_grid.addWidget(QLabel("تعداد تلاش مجدد خودکار:"), 1, 0)
        self.retry_spin = QSpinBox()
        self.retry_spin.setRange(0, 5)
        perf_grid.addWidget(self.retry_spin, 1, 1)

        perf_grid.addWidget(QLabel("تاخیر کنترل نرخ بین پروب‌ها (میلی‌ثانیه):"), 2, 0)
        self.rate_limit_spin = QSpinBox()
        self.rate_limit_spin.setRange(0, 5000)
        self.rate_limit_spin.setSingleStep(50)
        perf_grid.addWidget(self.rate_limit_spin, 2, 1)

        c_layout.addWidget(perf_box)

        # Section 3: Appearance
        app_box, app_grid = self._create_card_section("رابط کاربری و ظاهر")

        app_grid.addWidget(QLabel("حالت تم برنامه:"), 0, 0)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["حالت تیره پیش‌فرض نئونی (Dark Mode)"])
        self.theme_combo.setEnabled(False)
        self.theme_combo.setToolTip("برنامه به طور اختصاصی روی تم تاریک نئونی قفل شده است")
        app_grid.addWidget(self.theme_combo, 0, 1)

        app_grid.addWidget(QLabel("اندازه فونت (پیکسل):"), 1, 0)
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(10, 18)
        app_grid.addWidget(self.font_size_spin, 1, 1)

        self.compact_table_chk = QCheckBox("فعال‌سازی جدول فشرده نتایج (تراکم بالاتر)")
        app_grid.addWidget(self.compact_table_chk, 2, 0, 1, 2)

        c_layout.addWidget(app_box)

        # Section 4: Logging & Diagnostics
        log_box, log_grid = self._create_card_section("ثبت گزارش‌ها و عیب‌یابی (Logs)")

        self.enable_log_chk = QCheckBox("فعال‌سازی ذخیره چرخشی فایل‌های لاگ محلی")
        log_grid.addWidget(self.enable_log_chk, 0, 0)

        log_grid.addWidget(QLabel("سطح گزارش‌گیری:"), 1, 0)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        log_grid.addWidget(self.log_level_combo, 1, 1)

        open_log_btn = QPushButton("باز کردن پوشه لاگ‌ها در فایل منیجر")
        open_log_btn.setIcon(get_icon("search", color=Colors.NEON_BLUE, size=14))
        open_log_btn.clicked.connect(self._open_log_folder)
        log_grid.addWidget(open_log_btn, 2, 0, 1, 2)

        c_layout.addWidget(log_box)

        # Section 5: Data Management & Export
        data_box, data_grid = self._create_card_section("ذخیره‌سازی داده‌ها و ماندگاری")

        data_grid.addWidget(QLabel("مدت نگهداری تاریخچه (روز):"), 0, 0)
        self.retention_spin = QSpinBox()
        self.retention_spin.setRange(1, 365)
        data_grid.addWidget(self.retention_spin, 0, 1)

        data_grid.addWidget(QLabel("پوشه پیش‌فرض ذخیره خروجی:"), 1, 0)
        exp_row = QHBoxLayout()
        self.export_dir_input = QLineEdit()
        exp_row.addWidget(self.export_dir_input)

        browse_exp_btn = QPushButton("انتخاب پوشه...")
        browse_exp_btn.clicked.connect(self._browse_export_dir)
        exp_row.addWidget(browse_exp_btn)
        data_grid.addLayout(exp_row, 1, 1)

        c_layout.addWidget(data_box)

        # Section 6: Ownership & Creator Information
        about_box, about_grid = self._create_card_section("حقوق مالکیت نرم‌افزار و اطلاعات سازنده")

        team_title = QLabel("تیم نیکاتور (Nikator Team)")
        team_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        about_grid.addWidget(team_title, 0, 0)

        team_rights = QLabel(
            "تمامی حقوق این برنامه برای تیم نیکاتور میباشد و هر گونه کپی برداری از ان دامن شما را خواهد گرفت و به خاک سیاه خواهد نشاند با تشکر تیم نیکاتور"
        )
        team_rights.setStyleSheet(f"font-size: 11px; color: {Colors.NEON_BLUE}; font-weight: 600; line-height: 1.4;")
        team_rights.setWordWrap(True)
        about_grid.addWidget(team_rights, 0, 1)

        about_grid.addWidget(QLabel("سازنده و پشتیبانی:"), 1, 0)
        tg_info_row = QHBoxLayout()
        tg_lbl = QLabel("تلگرام: @Zeusskyofficial")
        tg_lbl.setStyleSheet("font-size: 12px; color: #FFFFFF; font-weight: 700;")
        tg_info_row.addWidget(tg_lbl)

        open_tg_btn = QPushButton("ارتباط در تلگرام")
        open_tg_btn.setIcon(get_icon("globe", color=Colors.NEON_BLUE, size=13))
        open_tg_btn.setCursor(Qt.PointingHandCursor)
        open_tg_btn.clicked.connect(self._open_telegram)
        tg_info_row.addWidget(open_tg_btn)
        tg_info_row.addStretch()
        about_grid.addLayout(tg_info_row, 1, 1)

        c_layout.addWidget(about_box)

        scroll.setWidget(content)
        main_layout.addWidget(scroll)

        # Bottom Save / Reset Button Row
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        reset_btn = QPushButton("بازنشانی به پیش‌فرض")
        reset_btn.clicked.connect(self._reset_defaults)
        btn_row.addWidget(reset_btn)

        save_btn = QPushButton("ذخیره تنظیمات")
        save_btn.setProperty("class", "PrimaryBtn")
        save_btn.setIcon(get_icon("check", color="#FFFFFF", size=14))
        save_btn.clicked.connect(self.save_settings)
        btn_row.addWidget(save_btn)

        main_layout.addLayout(btn_row)

    def _create_card_section(self, title: str) -> tuple[QFrame, QGridLayout]:
        frame = QFrame()
        frame.setProperty("class", "CardFrame")
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.DARK_SURFACE};
                border: 1px solid {Colors.DARK_BORDER};
                border-radius: 8px;
            }}
        """)
        outer_layout = QVBoxLayout(frame)
        outer_layout.setContentsMargins(14, 12, 14, 12)
        outer_layout.setSpacing(10)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        outer_layout.addWidget(title_lbl)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)
        outer_layout.addLayout(grid)

        return frame, grid

    def _load_settings_into_ui(self) -> None:
        self.dns_timeout_spin.setValue(self.settings.dns_timeout)
        self.tcp_timeout_spin.setValue(self.settings.tcp_timeout)
        self.tls_timeout_spin.setValue(self.settings.tls_timeout)
        self.http_timeout_spin.setValue(self.settings.http_timeout)
        self.dns_servers_input.setText(", ".join(self.settings.custom_dns_servers))

        self.concurrency_spin.setValue(self.settings.max_concurrency)
        self.retry_spin.setValue(self.settings.retry_count)
        self.rate_limit_spin.setValue(self.settings.rate_limit_delay_ms)

        self.theme_combo.setCurrentText("حالت تیره پیش‌فرض نئونی (Dark Mode)")
        self.font_size_spin.setValue(self.settings.font_size)
        self.compact_table_chk.setChecked(self.settings.compact_table)

        self.enable_log_chk.setChecked(self.settings.enable_logging)
        self.log_level_combo.setCurrentText(self.settings.log_level)

        self.retention_spin.setValue(self.settings.history_retention_days)
        self.export_dir_input.setText(self.settings.export_directory)

    def save_settings(self) -> None:
        """Persist settings values to disk and notify application."""
        self.settings.dns_timeout = float(self.dns_timeout_spin.value())
        self.settings.tcp_timeout = float(self.tcp_timeout_spin.value())
        self.settings.tls_timeout = float(self.tls_timeout_spin.value())
        self.settings.http_timeout = float(self.http_timeout_spin.value())

        dns_text = self.dns_servers_input.text().strip()
        self.settings.custom_dns_servers = [s.strip() for s in dns_text.split(",") if s.strip()]

        self.settings.max_concurrency = self.concurrency_spin.value()
        self.settings.retry_count = self.retry_spin.value()
        self.settings.rate_limit_delay_ms = self.rate_limit_spin.value()

        # Enforce dark mode permanently
        self.settings.theme_mode = "dark"

        self.settings.font_size = self.font_size_spin.value()
        self.settings.compact_table = self.compact_table_chk.isChecked()

        self.settings.enable_logging = self.enable_log_chk.isChecked()
        self.settings.log_level = self.log_level_combo.currentText()

        self.settings.history_retention_days = self.retention_spin.value()
        self.settings.export_directory = self.export_dir_input.text().strip()

        self.settings_mgr.settings = self.settings
        self.settings_mgr.save()

        ToastNotification("تنظیمات با موفقیت ذخیره شد", self)
        self.settings_applied.emit()

    def _open_telegram(self) -> None:
        import webbrowser
        webbrowser.open("https://t.me/Zeusskyofficial")

    def _reset_defaults(self) -> None:
        defaults = ApplicationSettings()
        self.dns_timeout_spin.setValue(defaults.dns_timeout)
        self.tcp_timeout_spin.setValue(defaults.tcp_timeout)
        self.tls_timeout_spin.setValue(defaults.tls_timeout)
        self.http_timeout_spin.setValue(defaults.http_timeout)
        self.dns_servers_input.setText(", ".join(defaults.custom_dns_servers))
        self.concurrency_spin.setValue(defaults.max_concurrency)
        self.retry_spin.setValue(defaults.retry_count)
        self.rate_limit_spin.setValue(defaults.rate_limit_delay_ms)
        self.theme_combo.setCurrentText("حالت تیره پیش‌فرض نئونی (Dark Mode)")
        self.font_size_spin.setValue(defaults.font_size)
        self.compact_table_chk.setChecked(defaults.compact_table)
        self.enable_log_chk.setChecked(defaults.enable_logging)
        self.log_level_combo.setCurrentText(defaults.log_level)
        self.retention_spin.setValue(defaults.history_retention_days)
        ToastNotification("تنظیمات به حالت پیش‌فرض بازنشانی شد", self)

    def _open_log_folder(self) -> None:
        log_dir = get_log_dir()
        if sys.platform == "win32":
            os.startfile(str(log_dir))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(log_dir)])
        else:
            subprocess.Popen(["xdg-open", str(log_dir)])

    def _browse_export_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "انتخاب پوشه پیش‌فرض خروجی")
        if folder:
            self.export_dir_input.setText(folder)
