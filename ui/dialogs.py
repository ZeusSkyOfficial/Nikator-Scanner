"""Custom modal dialogs for Nikator Scanner.
Includes confirmation prompts, detailed inspection modals, and about info.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from models.results import ScanResult
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors


class ConfirmDialog(QDialog):
    """Modern confirmation dialog for destructive or critical actions."""

    def __init__(
        self,
        title: str,
        message: str,
        confirm_label: str = "تایید",
        is_danger: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(400, 180)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        msg_layout = QHBoxLayout()
        msg_layout.setSpacing(14)

        icon_lbl = QLabel()
        icon_name = "warning" if is_danger else "shield"
        color = Colors.FAILED_RED if is_danger else Colors.NEON_BLUE
        icon_lbl.setPixmap(get_pixmap(icon_name, color=color, size=32))
        msg_layout.addWidget(icon_lbl)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(4)
        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #FFFFFF;")
        m_lbl = QLabel(message)
        m_lbl.setWordWrap(True)
        m_lbl.setStyleSheet(f"font-size: 12px; color: {Colors.DARK_TEXT_SECONDARY};")
        text_layout.addWidget(t_lbl)
        text_layout.addWidget(m_lbl)
        msg_layout.addLayout(text_layout)

        layout.addLayout(msg_layout)
        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        btn_layout.addStretch()

        cancel_btn = QPushButton("انصراف")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        confirm_btn = QPushButton(confirm_label)
        if is_danger:
            confirm_btn.setProperty("class", "DangerBtn")
        else:
            confirm_btn.setProperty("class", "PrimaryBtn")
        confirm_btn.clicked.connect(self.accept)
        btn_layout.addWidget(confirm_btn)

        layout.addLayout(btn_layout)


class ResultDetailsDialog(QDialog):
    """Full-screen / large inspection modal for viewing full raw scan data, certificate, and headers."""

    def __init__(self, result: ScanResult, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"بررسی تفصیلی عیب‌یابی — {result.target.hostname}")
        self.resize(750, 580)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header Info
        header_frame = QFrame()
        header_frame.setProperty("class", "CardFrame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(14, 10, 14, 10)

        title_lbl = QLabel(f"هدف: {result.target.hostname} (SNI: {result.target.sni})")
        title_lbl.setStyleSheet(f"color: {Colors.NEON_BLUE}; font-size: 14px; font-weight: 700;")
        header_layout.addWidget(title_lbl)
        header_layout.addStretch()

        status_labels = {
            "success": "موفق",
            "partial": "هشدار/جزئی",
            "failed": "ناموفق",
            "timeout": "تایم‌اوت",
            "error": "خطا",
        }
        stat_text = status_labels.get(result.status.value, result.status.label)
        status_lbl = QLabel(f"وضعیت نهایی: {stat_text}")
        stat_color = Colors.SUCCESS_GREEN if result.status.value == "success" else (Colors.WARNING_AMBER if result.status.value == "partial" else Colors.FAILED_RED)
        status_lbl.setStyleSheet(f"color: {stat_color}; font-size: 13px; font-weight: 700;")
        header_layout.addWidget(status_lbl)

        layout.addWidget(header_frame)

        # Multi-tab view or text details
        text_area = QTextEdit()
        text_area.setReadOnly(True)
        text_area.setStyleSheet(f"""
            QTextEdit {{
                font-family: Consolas, "Courier New", monospace;
                font-size: 12px;
                background-color: {Colors.DARK_SURFACE_ALT};
                color: #E2E8F0;
                line-height: 1.5;
            }}
        """)

        # Build detailed report
        lines = [
            "==================================================================",
            f"  گزارش و ردیابی تشخیصی شبکه: {result.target.hostname}",
            "==================================================================",
            f"زمان ثبت تست         : {result.timestamp}",
            f"تاخیر کل             : {result.display_latency}",
            f"آی‌پی و پورت مقصد    : {result.display_ip}:{result.target.port}",
            f"هدر SNI استفاده‌شده  : {result.target.sni}",
            "",
            "--- تفکیک و وضوح دی‌ان‌اس (DNS Resolution) -------------------------",
            f"وضعیت تفکیک          : {'موفق' if result.dns.resolved else 'ناموفق'}",
            f"تاخیر DNS            : {result.dns.latency_ms:.2f} ms",
            f"آدرس‌های IPv4         : {', '.join(result.dns.ipv4_addresses) or 'ندارد'}",
            f"آدرس‌های IPv6         : {', '.join(result.dns.ipv6_addresses) or 'ندارد'}",
            f"رکوردهای CNAME       : {', '.join(result.dns.cnames) or 'ندارد'}",
            f"پیام خطای DNS        : {result.dns.error or 'ندارد'}",
            "",
            "--- دست‌تکانی و اتصال تی‌سی‌پی (TCP Handshake) ----------------------",
            f"وضعیت اتصال TCP      : {'موفق' if result.tcp.connected else 'ناموفق'}",
            f"تاخیر اتصال TCP      : {result.tcp.latency_ms:.2f} ms",
            f"نقطه پایانی دوردست   : {result.tcp.remote_ip}:{result.tcp.port}",
            f"پیام خطای TCP        : {result.tcp.error or 'ندارد'}",
            "",
            "--- مذاکره و هندشیک تی‌ال‌اس (TLS / SNI Negotiation) ---------------",
            f"هندشیک TLS           : {'موفق' if result.tls.handshake_success else 'ناموفق'}",
            f"نسخه TLS توافق‌شده   : {result.tls.tls_version or 'نامشخص'}",
            f"مجموعه رمزنگاری      : {result.tls.cipher or 'نامشخص'}",
            f"پروتکل ALPN انتخابی  : {result.tls.alpn_selected or 'ندارد'}",
            f"تاخیر هندشیک TLS     : {result.tls.latency_ms:.2f} ms",
            f"تطابق گواهی با SNI   : {'بله (تطابق کامل)' if result.tls.certificate_matches_sni else 'خیر (عدم تطابق گواهی)'}",
            f"پیام خطای TLS        : {result.tls.error or 'ندارد'}",
            "",
            "--- مشخصات گواهی دیجیتال X.509 -------------------------------------",
            f"موضوع (Subject)      : {result.tls.certificate.subject or 'نامشخص'}",
            f"صادرکننده (Issuer)   : {result.tls.certificate.issuer or 'نامشخص'}",
            f"معتبر از تاریخ       : {result.tls.certificate.valid_from or 'نامشخص'}",
            f"معتبر تا تاریخ       : {result.tls.certificate.valid_until or 'نامشخص'}",
            f"منقضی شده            : {'بله' if result.tls.certificate.is_expired else 'خیر'}",
            f"الگوریتم امضا        : {result.tls.certificate.signature_algorithm or 'نامشخص'}",
            f"شماره سریال          : {result.tls.certificate.serial_number or 'نامشخص'}",
            f"اثر انگشت SHA256     : {result.tls.certificate.fingerprint_sha256 or 'نامشخص'}",
            f"نام‌های جایگزین (SAN): {', '.join(result.tls.certificate.subject_alt_names) or 'ندارد'}",
            "",
            "--- تست لایه کاربردی (HTTP / HTTPS Probe) -------------------------",
            f"دسترسی‌پذیری وب‌سرور : {'بله' if result.http.reachable else 'خیر'}",
            f"کد وضعیت HTTP        : {result.http.status_code or 'نامشخص'}",
            f"هدر سرور             : {result.http.server_header or 'نامشخص'}",
            f"نوع محتوا (Content)  : {result.http.content_type or 'نامشخص'}",
            f"آدرس تغییر مسیر      : {result.http.redirect_url or 'ندارد'}",
            f"تاخیر درخواست HTTP   : {result.http.latency_ms:.2f} ms",
            f"پیام خطای HTTP       : {result.http.error or 'ندارد'}",
        ]

        if result.tls.certificate.raw_pem:
            lines.extend([
                "",
                "--- محتوای خام گواهی سرور (PEM) -----------------------------------",
                result.tls.certificate.raw_pem,
            ])

        text_area.setPlainText("\n".join(lines))
        layout.addWidget(text_area)

        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("بستن")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)


class AboutDialog(QDialog):
    """About dialog providing suite details and legal diagnostics statement."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("درباره نیکاتور اسکنر (Nikator Scanner)")
        self.setFixedSize(520, 470)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(get_pixmap("network", color=Colors.NEON_BLUE, size=44))
        icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_lbl)

        title = QLabel("Nikator Scanner")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF; letter-spacing: 0.5px;")
        layout.addWidget(title)

        subtitle = QLabel("SNI • DNS • TLS • سوئیت تخصصی عیب‌یابی شبکه")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"font-size: 12px; color: {Colors.NEON_BLUE}; font-weight: 600;")
        layout.addWidget(subtitle)

        desc = QLabel(
            "نیکاتور اسکنر (Nikator Scanner) یک ابزار تخصصی و قدرتمند برای اسکن و عیب‌یابی دقیق لایه‌های شبکه، "
            "کشف و ارزیابی SNI، تست کانفیگ‌های شبکه و استخراج آی‌پی‌های تمیز و پایدار است."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet(f"font-size: 11px; color: {Colors.DARK_TEXT_SECONDARY}; line-height: 1.5;")
        layout.addWidget(desc)

        # Team & Rights Box
        team_box = QFrame()
        team_box.setStyleSheet(f"""
            QFrame {{
                background-color: {Colors.DARK_SURFACE_ALT};
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        t_layout = QVBoxLayout(team_box)
        t_layout.setContentsMargins(10, 8, 10, 8)
        t_layout.setSpacing(4)

        t_title = QLabel("تیم نیکاتور (Nikator Team)")
        t_title.setAlignment(Qt.AlignCenter)
        t_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        t_layout.addWidget(t_title)

        rights = QLabel(
            "تمامی حقوق این برنامه برای تیم نیکاتور میباشد و هر گونه کپی برداری از ان دامن شما را خواهد گرفت و به خاک سیاه خواهد نشاند با تشکر تیم نیکاتور"
        )
        rights.setAlignment(Qt.AlignCenter)
        rights.setWordWrap(True)
        rights.setStyleSheet(f"font-size: 10.5px; color: {Colors.NEON_BLUE}; font-weight: 600; line-height: 1.4;")
        t_layout.addWidget(rights)

        layout.addWidget(team_box)

        # Telegram Button
        tg_btn = QPushButton("ارتباط با سازنده در تلگرام: @Zeusskyofficial")
        tg_btn.setIcon(get_icon("globe", color="#FFFFFF", size=14))
        tg_btn.setCursor(Qt.PointingHandCursor)
        tg_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 212, 255, 0.18);
                color: #FFFFFF;
                border: 1px solid #00d4ff;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton:hover {
                background-color: rgba(0, 212, 255, 0.32);
            }
        """)
        tg_btn.clicked.connect(self._open_telegram)
        layout.addWidget(tg_btn)

        layout.addStretch()

        close_btn = QPushButton("بستن")
        close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet(f"background-color: {Colors.PRIMARY_BLUE}; color: #FFFFFF; font-weight: 600; padding: 6px;")
        layout.addWidget(close_btn)

    def _open_telegram(self) -> None:
        import webbrowser
        webbrowser.open("https://t.me/Zeusskyofficial")
