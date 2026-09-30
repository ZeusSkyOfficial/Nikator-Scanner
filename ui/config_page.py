"""Configuration Tester page for Nikator Scanner.
Safely extracts endpoints from user-pasted network configs (URIs, JSON, YAML-like)
and runs DNS/TCP/TLS diagnostics without executing arbitrary code.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime
import threading
from typing import Dict, List, Optional

from PySide6.QtCore import QPoint, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models.results import ApplicationSettings, DNSResult, ScanResult, ScanStatus, ScanTarget, TCPResult, TLSResult
from network.clean_ips import get_candidate_clean_ips
from network.resolver import DNSResolver
from network.tcp import TCPTester
from network.tls import TLSTester
from parsers.config_parser import ParsedEndpoint, SafeConfigParser
from ui.dialogs import ResultDetailsDialog
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import CircularStatusIndicator, ToastNotification
from utils.clipboard import copy_text_to_clipboard
from utils.exporters import export_to_csv, export_to_json, export_to_txt


class ConfigTesterWorker(QThread):
    """Executes network diagnostics on extracted endpoints or scans clean IPs for configs."""

    progress_signal = Signal(int, int, str)
    result_signal = Signal(object, object)  # ParsedEndpoint, ScanResult
    finished_signal = Signal()

    def __init__(
        self,
        endpoints: List[ParsedEndpoint],
        target_clean_count: int = 10,
        clean_ip_mode: bool = True,
        source_type: str = "combined",
        timeout: float = 3.5,
        concurrency: int = 15,
        retry_count: int = 1,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.endpoints = endpoints
        self.target_clean_count = max(1, target_clean_count)
        self.clean_ip_mode = clean_ip_mode
        self.source_type = source_type
        self.timeout = timeout
        self.concurrency = concurrency
        self.retry_count = retry_count
        self.dns_resolver = DNSResolver(timeout=timeout)
        self.tcp_tester = TCPTester(timeout=timeout)
        self.tls_tester = TLSTester(timeout=timeout)
        self._is_cancelled = threading.Event()

    def cancel(self) -> None:
        self._is_cancelled.set()

    def run(self) -> None:
        if not self.endpoints:
            self.finished_signal.emit()
            return

        if self.clean_ip_mode:
            self._run_clean_ip_mode()
        else:
            self._run_standard_mode()

        self.finished_signal.emit()

    def _run_clean_ip_mode(self) -> None:
        """Scan candidate clean IPs for each endpoint until target_clean_count is satisfied."""
        for ep in self.endpoints:
            if self._is_cancelled.is_set():
                break

            self.progress_signal.emit(0, self.target_clean_count, f"تفکیک دامنه {ep.hostname}...")
            dns_res = self.dns_resolver.resolve(ep.hostname)

            # Generate candidate pool
            if "فقط رکوردهای DNS" in self.source_type:
                cand_ips = list(dns_res.ipv4_addresses)
            elif "فقط رنج‌های کلودفلر" in self.source_type:
                cand_ips = get_candidate_clean_ips(
                    resolved_ips=[],
                    count=max(self.target_clean_count * 5, 50),
                    include_cloudflare_ranges=True,
                )
            else:  # combined
                cand_ips = get_candidate_clean_ips(
                    resolved_ips=dns_res.ipv4_addresses,
                    count=max(self.target_clean_count * 5, 50),
                    include_cloudflare_ranges=True,
                )

            if not cand_ips:
                cand_ips = [ep.hostname]

            ep_found = 0
            tested = 0
            total_cand = len(cand_ips)

            def test_candidate(cand_ip: str) -> tuple[ParsedEndpoint, ScanResult]:
                cand_ep = ParsedEndpoint(
                    raw_entry=ep.raw_entry,
                    full_config=ep.full_config,
                    hostname=ep.hostname,
                    port=ep.port,
                    sni=ep.sni or ep.hostname,
                    protocol=ep.protocol,
                    use_tls=ep.use_tls,
                    alpn=ep.alpn,
                    remarks=f"{ep.remarks or ep.hostname} ({cand_ip})",
                    clean_ip=cand_ip,
                )
                target = ScanTarget(
                    hostname=ep.hostname,
                    ip=cand_ip,
                    port=ep.port,
                    sni=ep.sni or ep.hostname,
                    protocol=ep.protocol,
                )
                res = ScanResult(target=target, timestamp=datetime.now().isoformat())
                res.dns = dns_res

                # 1. TCP Handshake
                tcp_res = self.tcp_tester.test_connection(cand_ip, ep.port)
                res.tcp = tcp_res
                if not tcp_res.connected:
                    res.status = ScanStatus.FAILED
                    res.total_latency_ms = tcp_res.latency_ms
                    return cand_ep, res

                # 2. TLS Handshake with config SNI
                if ep.use_tls:
                    tls_res = self.tls_tester.test_tls(cand_ip, ep.port, sni=ep.sni or ep.hostname)
                    res.tls = tls_res
                    res.total_latency_ms = tcp_res.latency_ms + tls_res.latency_ms
                    if tls_res.handshake_success:
                        res.status = ScanStatus.SUCCESS
                    else:
                        res.status = ScanStatus.PARTIAL
                else:
                    res.total_latency_ms = tcp_res.latency_ms
                    res.status = ScanStatus.SUCCESS

                return cand_ep, res

            max_workers = min(self.concurrency, max(1, total_cand))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(test_candidate, ip): ip for ip in cand_ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    if self._is_cancelled.is_set():
                        break
                    try:
                        cand_ep, res = future.result()
                    except Exception as e:
                        ip_val = future_to_ip[future]
                        cand_ep = ParsedEndpoint(
                            raw_entry=ep.raw_entry,
                            full_config=ep.full_config,
                            hostname=ep.hostname,
                            port=ep.port,
                            sni=ep.sni or ep.hostname,
                            protocol=ep.protocol,
                            use_tls=ep.use_tls,
                            clean_ip=ip_val,
                        )
                        target = ScanTarget(hostname=ep.hostname, ip=ip_val, port=ep.port, sni=ep.sni)
                        res = ScanResult(target=target, status=ScanStatus.FAILED, notes=str(e))

                    tested += 1
                    if res.status == ScanStatus.SUCCESS:
                        ep_found += 1

                    self.result_signal.emit(cand_ep, res)
                    self.progress_signal.emit(
                        min(ep_found, self.target_clean_count),
                        self.target_clean_count,
                        f"یافت‌شده: {ep_found} از {self.target_clean_count} آی‌پی تمیز (تست‌شده: {tested})",
                    )

                    # Stop if we found enough clean IPs for this endpoint
                    if ep_found >= self.target_clean_count:
                        for f in future_to_ip:
                            f.cancel()
                        break

    def _run_standard_mode(self) -> None:
        """Standard 1-to-1 endpoint test."""
        total = len(self.endpoints)
        tested = 0

        def test_ep(ep: ParsedEndpoint) -> tuple[ParsedEndpoint, ScanResult]:
            target = ScanTarget(
                hostname=ep.hostname,
                port=ep.port,
                sni=ep.sni or ep.hostname,
                protocol=ep.protocol,
            )
            res = ScanResult(target=target, timestamp=datetime.now().isoformat())

            # 1. DNS Resolution
            dns_res = self.dns_resolver.resolve(ep.hostname)
            res.dns = dns_res
            if not dns_res.resolved:
                res.status = ScanStatus.FAILED
                res.total_latency_ms = dns_res.latency_ms
                return ep, res

            primary_ip = dns_res.primary_ip
            target.ip = primary_ip

            # 2. TCP Handshake
            tcp_res = self.tcp_tester.test_connection(primary_ip, ep.port)
            res.tcp = tcp_res
            if not tcp_res.connected:
                res.status = ScanStatus.FAILED
                res.total_latency_ms = dns_res.latency_ms + tcp_res.latency_ms
                return ep, res

            # 3. TLS Check
            if ep.use_tls:
                tls_res = self.tls_tester.test_tls(primary_ip, ep.port, sni=ep.sni or ep.hostname)
                res.tls = tls_res
                res.total_latency_ms = dns_res.latency_ms + tcp_res.latency_ms + tls_res.latency_ms
                if tls_res.handshake_success:
                    res.status = ScanStatus.SUCCESS
                else:
                    res.status = ScanStatus.PARTIAL
            else:
                res.total_latency_ms = dns_res.latency_ms + tcp_res.latency_ms
                res.status = ScanStatus.SUCCESS

            return ep, res

        max_workers = min(self.concurrency, max(1, total))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ep = {executor.submit(test_ep, ep): ep for ep in self.endpoints}
            for future in concurrent.futures.as_completed(future_to_ep):
                if self._is_cancelled.is_set():
                    break
                try:
                    ep, res = future.result()
                except Exception as e:
                    ep = future_to_ep[future]
                    target = ScanTarget(hostname=ep.hostname, port=ep.port, sni=ep.sni)
                    res = ScanResult(target=target, status=ScanStatus.FAILED, notes=str(e))

                tested += 1
                self.result_signal.emit(ep, res)
                self.progress_signal.emit(tested, total, f"تست‌شده: {ep.hostname}:{ep.port}")


class ConfigPage(QWidget):
    """Configuration Tester and Clean IP Scanner module view."""

    def __init__(self, settings: ApplicationSettings, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.parsed_endpoints: List[ParsedEndpoint] = []
        self.results_data: List[tuple[ParsedEndpoint, ScanResult]] = []
        self.worker: Optional[ConfigTesterWorker] = None

        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)
        title_lbl = QLabel("تست‌کننده کانفیگ و استخراج آی‌پی تمیز")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF;")
        sub_lbl = QLabel("تجزیه کانفیگ‌های شبکه (VLESS، VMess، Trojan، Clash) و استخراج خودکار آی‌پی‌های تمیز و کم‌پینگ")
        sub_lbl.setStyleSheet(f"font-size: 12px; color: {Colors.DARK_TEXT_SECONDARY};")
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(sub_lbl)
        layout.addLayout(header_layout)

        # Body Splitter: Top Input & Settings, Bottom Results Table
        splitter = QSplitter(Qt.Vertical)

        # --- TOP PANEL: Input Config & Controls ---
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(12)

        # Left: Multi-line paste area
        input_frame = QFrame()
        input_frame.setProperty("class", "CardFrame")
        in_layout = QVBoxLayout(input_frame)
        in_layout.setContentsMargins(12, 10, 12, 10)
        in_layout.setSpacing(6)

        in_header = QHBoxLayout()
        in_title = QLabel("ورود کانفیگ‌های شبکه / لیست لینک‌ها:")
        in_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        in_header.addWidget(in_title)
        in_header.addStretch()

        import_file_btn = QPushButton("وارد کردن فایل...")
        import_file_btn.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=14))
        import_file_btn.clicked.connect(self._import_config_file)
        in_header.addWidget(import_file_btn)
        in_layout.addLayout(in_header)

        self.config_input = QPlainTextEdit()
        self.config_input.setPlaceholderText(
            "کانفیگ‌ها یا لینک‌های خود را اینجا جای‌گذاری کنید (vless://, vmess://, trojan://, ss://, https://)\n"
            "یا فرمت‌های Clash، YAML/JSON یا host:port:\n\n"
            "مثال:\n"
            "vless://user@worker.dev:443?security=tls&sni=worker.dev#MyConfig\n"
            "cloudflare.com:443"
        )
        self.config_input.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        in_layout.addWidget(self.config_input)

        parse_btn = QPushButton("تجزیه و شناسایی کانفیگ")
        parse_btn.setProperty("class", "PrimaryBtn")
        parse_btn.setFixedHeight(34)
        parse_btn.setIcon(get_icon("search", color="#FFFFFF", size=14))
        parse_btn.clicked.connect(self.parse_input)
        in_layout.addWidget(parse_btn)

        top_layout.addWidget(input_frame, stretch=3)

        # Right: Parameters & Scan Controls Card
        ctrl_frame = QFrame()
        ctrl_frame.setProperty("class", "CardFrame")
        ctrl_frame.setFixedWidth(310)
        c_layout = QVBoxLayout(ctrl_frame)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        ctrl_title = QLabel("تنظیمات اسکن آی‌پی تمیز")
        ctrl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        c_layout.addWidget(ctrl_title)

        # Clean IP Mode Checkbox
        self.clean_ip_mode_chk = QCheckBox("✨ اسکن آی‌پی‌های تمیز (Clean IP)")
        self.clean_ip_mode_chk.setChecked(True)
        self.clean_ip_mode_chk.setStyleSheet("font-weight: 700; color: #38BDF8;")
        self.clean_ip_mode_chk.toggled.connect(self._on_clean_mode_toggled)
        c_layout.addWidget(self.clean_ip_mode_chk)

        # Target Clean Count Spinbox
        self.limit_lbl = QLabel("تعداد آی‌پی تمیز درخواستی:")
        c_layout.addWidget(self.limit_lbl)
        self.limit_spin = QSpinBox()
        self.limit_spin.setFixedHeight(34)
        self.limit_spin.setRange(1, 500)
        self.limit_spin.setValue(10)
        self.limit_spin.setToolTip("تعداد آی‌پی‌های سالمی که می‌خواهید برای کانفیگ پیدا شود")
        c_layout.addWidget(self.limit_spin)

        # Candidate IP Sources
        self.source_lbl = QLabel("منبع آی‌پی‌های کاندیدا:")
        c_layout.addWidget(self.source_lbl)
        self.source_combo = QComboBox()
        self.source_combo.setFixedHeight(34)
        self.source_combo.addItems([
            "رنج‌های ابری کلودفلر + DNS (پیش‌فرض)",
            "فقط رنج‌های کلودفلر (Cloudflare Ranges)",
            "فقط رکوردهای DNS دامنه کانفیگ",
        ])
        c_layout.addWidget(self.source_combo)

        # Timeout
        c_layout.addWidget(QLabel("تایم‌اوت پروب (ثانیه):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setFixedHeight(34)
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(int(self.settings.tcp_timeout))
        c_layout.addWidget(self.timeout_spin)

        # Concurrency
        c_layout.addWidget(QLabel("تعداد ترد همزمان:"))
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setFixedHeight(34)
        self.concurrency_spin.setRange(1, 100)
        self.concurrency_spin.setValue(20)
        c_layout.addWidget(self.concurrency_spin)

        c_layout.addStretch()

        # Action Buttons
        self.start_btn = QPushButton("شروع اسکن آی‌پی‌های تمیز")
        self.start_btn.setProperty("class", "PrimaryBtn")
        self.start_btn.setFixedHeight(38)
        self.start_btn.setIcon(get_icon("play", color="#FFFFFF", size=16))
        self.start_btn.clicked.connect(self.start_test)
        c_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("توقف")
        self.stop_btn.setProperty("class", "DangerBtn")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.setIcon(get_icon("stop", color="#FFFFFF", size=14))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_test)
        c_layout.addWidget(self.stop_btn)

        top_layout.addWidget(ctrl_frame, stretch=1)
        splitter.addWidget(top_widget)

        # --- BOTTOM PANEL: Results Table & Export ---
        bottom_widget = QWidget()
        b_layout = QVBoxLayout(bottom_widget)
        b_layout.setContentsMargins(0, 8, 0, 0)
        b_layout.setSpacing(8)

        # Progress bar & status
        p_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        p_row.addWidget(self.progress_bar)

        self.status_lbl = QLabel("آماده")
        self.status_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        p_row.addWidget(self.status_lbl)
        b_layout.addLayout(p_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels([
            "کانفیگ / شناسه",
            "دامنه / هاست",
            "آدرس IP تمیز",
            "پورت",
            "SNI",
            "پروتکل",
            "DNS",
            "TCP",
            "TLS",
            "پینگ",
            "وضعیت / جزئیات",
            "زمان",
            "عملیات",
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.setColumnWidth(0, 130)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        self.table.setColumnWidth(1, 140)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.setColumnWidth(2, 175)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(3, 50)
        header.setSectionResizeMode(4, QHeaderView.Interactive)
        self.table.setColumnWidth(4, 120)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setColumnWidth(5, 65)
        header.setSectionResizeMode(6, QHeaderView.Fixed)
        self.table.setColumnWidth(6, 45)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        self.table.setColumnWidth(7, 45)
        header.setSectionResizeMode(8, QHeaderView.Fixed)
        self.table.setColumnWidth(8, 45)
        header.setSectionResizeMode(9, QHeaderView.Interactive)
        self.table.setColumnWidth(9, 85)
        header.setSectionResizeMode(10, QHeaderView.Stretch)
        header.setSectionResizeMode(11, QHeaderView.Interactive)
        self.table.setColumnWidth(11, 75)
        header.setSectionResizeMode(12, QHeaderView.Fixed)
        self.table.setColumnWidth(12, 165)

        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemDoubleClicked.connect(self._on_double_clicked)
        b_layout.addWidget(self.table)

        # Export & Copy row
        exp_row = QHBoxLayout()

        self.copy_good_btn = QPushButton("کپی کانفیگ‌ها با آی‌پی‌های تمیز")
        self.copy_good_btn.setProperty("class", "PrimaryBtn")
        self.copy_good_btn.setIcon(get_icon("copy", color="#FFFFFF", size=14))
        self.copy_good_btn.clicked.connect(self._copy_working_configs)
        exp_row.addWidget(self.copy_good_btn)

        self.copy_ips_btn = QPushButton("کپی لیست آی‌پی‌های تمیز")
        self.copy_ips_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=12))
        self.copy_ips_btn.clicked.connect(self._copy_clean_ips_only)
        exp_row.addWidget(self.copy_ips_btn)

        clear_btn = QPushButton("پاکسازی جدول")
        clear_btn.setIcon(get_icon("trash", color=Colors.FAILED_RED, size=12))
        clear_btn.clicked.connect(self._clear_results)
        exp_row.addWidget(clear_btn)

        exp_row.addStretch()

        btn_txt = QPushButton("خروجی TXT")
        btn_txt.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_txt.clicked.connect(lambda: self._export_results("txt"))
        exp_row.addWidget(btn_txt)

        btn_csv = QPushButton("خروجی CSV")
        btn_csv.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_csv.clicked.connect(lambda: self._export_results("csv"))
        exp_row.addWidget(btn_csv)

        btn_json = QPushButton("خروجی JSON")
        btn_json.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_json.clicked.connect(lambda: self._export_results("json"))
        exp_row.addWidget(btn_json)

        b_layout.addLayout(exp_row)
        splitter.addWidget(bottom_widget)
        splitter.setSizes([260, 400])

        layout.addWidget(splitter)

    def _on_clean_mode_toggled(self, checked: bool) -> None:
        if checked:
            self.limit_lbl.setText("تعداد آی‌پی تمیز درخواستی:")
            self.start_btn.setText("شروع اسکن آی‌پی‌های تمیز")
            self.source_lbl.setVisible(True)
            self.source_combo.setVisible(True)
        else:
            self.limit_lbl.setText("حداکثر تعداد کانفیگ:")
            self.start_btn.setText("شروع تست کانفیگ‌ها")
            self.source_lbl.setVisible(False)
            self.source_combo.setVisible(False)

    def _import_config_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "وارد کردن فایل کانفیگ", "", "فایل‌های کانفیگ (*.txt *.json *.yaml *.yml *.conf);;همه فایل‌ها (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.config_input.setPlainText(content)
                self.parse_input()
            except Exception:
                pass

    def parse_input(self) -> None:
        text = self.config_input.toPlainText().strip()
        if not text:
            self.status_lbl.setText("لطفاً ابتدا کانفیگ یا لینک‌ها را در کادر قرار دهید")
            return

        self.parsed_endpoints = SafeConfigParser.parse(text)
        if not self.parsed_endpoints:
            self.status_lbl.setText("هیچ کانفیگ معتبری در متن واردشده شناسایی نشد")
            return

        if self.clean_ip_mode_chk.isChecked():
            requested = self.limit_spin.value()
            self.status_lbl.setText(f"{len(self.parsed_endpoints)} کانفیگ شناسایی شد — آماده اسکن و استخراج {requested} آی‌پی تمیز.")
        else:
            limit = self.limit_spin.value()
            if len(self.parsed_endpoints) > limit:
                self.parsed_endpoints = self.parsed_endpoints[:limit]
            self.status_lbl.setText(f"{len(self.parsed_endpoints)} کانفیگ با موفقیت شناسایی شد و آماده تست است.")

    def start_test(self) -> None:
        if not self.parsed_endpoints:
            self.parse_input()
        if not self.parsed_endpoints:
            self.status_lbl.setText("هیچ هدف یا کانفیگ معتبری برای تست شناسایی نشد")
            return

        self.table.setRowCount(0)
        self.results_data.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        timeout = float(self.timeout_spin.value())
        concurrency = self.concurrency_spin.value()
        target_clean_count = self.limit_spin.value()
        clean_ip_mode = self.clean_ip_mode_chk.isChecked()
        source_type = self.source_combo.currentText()

        self.worker = ConfigTesterWorker(
            endpoints=self.parsed_endpoints,
            target_clean_count=target_clean_count,
            clean_ip_mode=clean_ip_mode,
            source_type=source_type,
            timeout=timeout,
            concurrency=concurrency,
            parent=self,
        )
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.result_signal.connect(self._on_result)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def stop_test(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(1000)

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("تست و اسکن متوقف شد")

    def _on_progress(self, tested: int, total: int, msg: str) -> None:
        pct = int((tested / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_lbl.setText(msg)

    def _on_result(self, ep: ParsedEndpoint, res: ScanResult) -> None:
        self.results_data.append((ep, res))
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 0: کانفیگ / شناسه
        entry_title = f"تمیز: {res.display_ip}" if ep.clean_ip else (ep.remarks or ep.hostname)
        title_item = QTableWidgetItem(entry_title)
        title_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.table.setItem(row, 0, title_item)

        # 1: دامنه / هاست
        host_item = QTableWidgetItem(ep.hostname)
        host_item.setForeground(QColor("#FFFFFF"))
        self.table.setItem(row, 1, host_item)

        # 2: آدرس IP تمیز (همراه با دکمه کپی تکی کنار آی‌پی)
        ip_widget = QWidget()
        ip_layout = QHBoxLayout(ip_widget)
        ip_layout.setContentsMargins(6, 2, 6, 2)
        ip_layout.setSpacing(6)
        ip_layout.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        ip_lbl = QLabel(res.display_ip)
        if res.status == ScanStatus.SUCCESS:
            ip_lbl.setStyleSheet(f"color: {Colors.NEON_BLUE}; font-weight: bold; font-size: 11px;")
        else:
            ip_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_MUTED}; font-size: 11px;")
        ip_layout.addWidget(ip_lbl)

        cp_single_btn = QPushButton()
        cp_single_btn.setFixedSize(22, 22)
        cp_single_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE if res.status == ScanStatus.SUCCESS else Colors.DARK_TEXT_MUTED, size=11))
        cp_single_btn.setToolTip(f"کپی آی‌پی تمیز: {res.display_ip}")
        cp_single_btn.setCursor(Qt.PointingHandCursor)
        cp_single_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 212, 255, 0.12);
                border: 1px solid rgba(0, 212, 255, 0.3);
                border-radius: 4px;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: rgba(0, 212, 255, 0.3);
                border: 1px solid #00d4ff;
            }
        """)
        cp_single_btn.clicked.connect(lambda _, ip_str=res.display_ip: self._copy_single_ip(ip_str))
        ip_layout.addWidget(cp_single_btn)
        ip_layout.addStretch()

        self.table.setCellWidget(row, 2, ip_widget)

        # 3: پورت
        self.table.setItem(row, 3, QTableWidgetItem(str(ep.port)))

        # 4: SNI
        self.table.setItem(row, 4, QTableWidgetItem(ep.sni or ep.hostname))

        # 5: پروتکل
        self.table.setItem(row, 5, QTableWidgetItem(ep.protocol.upper()))

        # 6: DNS
        dns_state = "success" if res.dns.resolved else "failed"
        self.table.setCellWidget(row, 6, self._wrap_ind(CircularStatusIndicator(dns_state, 16)))

        # 7: TCP
        tcp_state = "success" if res.tcp.connected else ("failed" if res.dns.resolved else "none")
        self.table.setCellWidget(row, 7, self._wrap_ind(CircularStatusIndicator(tcp_state, 16)))

        # 8: TLS
        if ep.use_tls:
            tls_state = "success" if res.tls.handshake_success else ("failed" if res.tcp.connected else "none")
        else:
            tls_state = "none"
        self.table.setCellWidget(row, 8, self._wrap_ind(CircularStatusIndicator(tls_state, 16)))

        # 9: پینگ / تاخیر
        lat_item = QTableWidgetItem(res.display_latency)
        if res.total_latency_ms < 150:
            lat_item.setForeground(QColor(Colors.SUCCESS_GREEN))
        elif res.total_latency_ms < 300:
            lat_item.setForeground(QColor(Colors.WARNING_AMBER))
        else:
            lat_item.setForeground(QColor(Colors.FAILED_RED))
        lat_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.table.setItem(row, 9, lat_item)

        # 10: خطا / وضعیت
        if res.status == ScanStatus.SUCCESS:
            status_text = "سالم و تمیز (پاسخ معتبر)"
            err_item = QTableWidgetItem(status_text)
            err_item.setForeground(QColor(Colors.SUCCESS_GREEN))
        else:
            err_msg = res.tls.error or res.tcp.error or res.dns.error or "عدم پاسخگویی"
            err_item = QTableWidgetItem(err_msg)
            err_item.setForeground(QColor(Colors.FAILED_RED))
        self.table.setItem(row, 10, err_item)

        # 11: زمان
        self.table.setItem(row, 11, QTableWidgetItem(res.timestamp.split("T")[-1][:8]))

        # 12: عملیات (کپی آی‌پی و کپی کانفیگ)
        act_box = QWidget()
        act_lay = QHBoxLayout(act_box)
        act_lay.setContentsMargins(4, 2, 4, 2)
        act_lay.setSpacing(6)
        act_lay.setAlignment(Qt.AlignCenter)

        btn_cp_ip = QPushButton("کپی IP")
        btn_cp_ip.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=11))
        btn_cp_ip.setFixedSize(68, 26)
        btn_cp_ip.setCursor(Qt.PointingHandCursor)
        btn_cp_ip.setStyleSheet("""
            QPushButton {
                background-color: rgba(0, 212, 255, 0.12);
                color: #00d4ff;
                border: 1px solid rgba(0, 212, 255, 0.35);
                border-radius: 4px;
                padding: 0px 4px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(0, 212, 255, 0.25);
                border: 1px solid #00d4ff;
            }
        """)
        btn_cp_ip.clicked.connect(lambda _, ip_str=res.display_ip: self._copy_single_ip(ip_str))
        act_lay.addWidget(btn_cp_ip)

        btn_cp_cfg = QPushButton("کپی کانفیگ")
        btn_cp_cfg.setIcon(get_icon("check", color=Colors.SUCCESS_GREEN if res.status == ScanStatus.SUCCESS else Colors.DARK_TEXT_MUTED, size=11))
        btn_cp_cfg.setFixedSize(80, 26)
        btn_cp_cfg.setCursor(Qt.PointingHandCursor)
        btn_cp_cfg.setStyleSheet("""
            QPushButton {
                background-color: rgba(34, 197, 94, 0.12);
                color: #22c55e;
                border: 1px solid rgba(34, 197, 94, 0.35);
                border-radius: 4px;
                padding: 0px 4px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(34, 197, 94, 0.25);
                border: 1px solid #22c55e;
            }
        """)
        btn_cp_cfg.clicked.connect(lambda _, ep_ref=ep, ip_str=res.display_ip: self._copy_single_config_with_ip(ep_ref, ip_str))
        act_lay.addWidget(btn_cp_cfg)

        self.table.setCellWidget(row, 12, act_box)

    def _wrap_ind(self, w: QWidget) -> QWidget:
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignCenter)
        lay.addWidget(w)
        return box

    def _on_finished(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        clean_count = sum(1 for _, res in self.results_data if res.status == ScanStatus.SUCCESS)
        self.status_lbl.setText(f"اسکن پایان یافت. تعداد {clean_count} آی‌پی تمیز و سالم برای کانفیگ پیدا شد.")

    def _on_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self.results_data):
            _, res = self.results_data[row]
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _copy_single_ip(self, ip: str) -> None:
        copy_text_to_clipboard(ip)
        self.status_lbl.setText(f"آدرس آی‌پی تمیز {ip} در کلیپ‌بورد کپی شد.")

    def _copy_single_config_with_ip(self, ep: ParsedEndpoint, ip: str) -> None:
        cfg = ep.generate_config_with_ip(ip)
        copy_text_to_clipboard(cfg)
        self.status_lbl.setText(f"کانفیگ با آی‌پی تمیز {ip} در کلیپ‌بورد کپی شد.")

    def _copy_working_configs(self) -> None:
        working = [
            ep.generate_config_with_ip(res.display_ip)
            for ep, res in self.results_data
            if res.status == ScanStatus.SUCCESS
        ]
        if working:
            copy_text_to_clipboard("\n".join(working))
            self.status_lbl.setText(f"تعداد {len(working)} کانفیگ با آی‌پی‌های تمیز جدید کپی شدند.")
        else:
            self.status_lbl.setText("هیچ کانفیگ سالمی برای کپی یافت نشد")

    def _copy_clean_ips_only(self) -> None:
        working_ips = [
            res.display_ip
            for _, res in self.results_data
            if res.status == ScanStatus.SUCCESS
        ]
        if working_ips:
            copy_text_to_clipboard("\n".join(working_ips))
            self.status_lbl.setText(f"تعداد {len(working_ips)} آدرس آی‌پی تمیز در کلیپ‌بورد کپی شد.")
        else:
            self.status_lbl.setText("هیچ آی‌پی تمیزی برای کپی یافت نشد")

    def _clear_results(self) -> None:
        self.table.setRowCount(0)
        self.results_data.clear()
        self.progress_bar.setValue(0)
        self.status_lbl.setText("آماده")

    def _show_context_menu(self, pos: QPoint) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results_data):
            return

        ep, res = self.results_data[row]
        menu = QMenu(self)
        c_cfg = menu.addAction(f"کپی کانفیگ با این آی‌پی تمیز ({res.display_ip})")
        c_ip = menu.addAction(f"کپی فقط آدرس IP: {res.display_ip}")
        c_sni = menu.addAction(f"کپی SNI: {ep.sni or ep.hostname}")
        c_host = menu.addAction(f"کپی نام هاست: {ep.hostname}")
        c_port = menu.addAction(f"کپی پورت: {ep.port}")
        menu.addSeparator()
        view_action = menu.addAction("مشاهده جزئیات کامل عیب‌یابی...")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == c_cfg:
            copy_text_to_clipboard(ep.generate_config_with_ip(res.display_ip))
            self.status_lbl.setText(f"کانفیگ با آی‌پی {res.display_ip} کپی شد")
        elif action == c_ip:
            copy_text_to_clipboard(res.display_ip)
            self.status_lbl.setText(f"آی‌پی {res.display_ip} کپی شد")
        elif action == c_host:
            copy_text_to_clipboard(ep.hostname)
        elif action == c_sni:
            copy_text_to_clipboard(ep.sni or ep.hostname)
        elif action == c_port:
            copy_text_to_clipboard(str(ep.port))
        elif action == view_action:
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _export_results(self, fmt: str) -> None:
        if not self.results_data:
            return

        fmt = fmt.lower()
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"خروجی به فرمت {fmt.upper()}",
            f"config_clean_ips.{fmt}",
            f"فایل‌های {fmt.upper()} (*.{fmt})",
        )
        if not file_path:
            return

        scan_results = [res for _, res in self.results_data]
        if fmt == "json":
            export_to_json(scan_results, file_path)
        elif fmt == "csv":
            export_to_csv(scan_results, file_path)
        elif fmt == "txt":
            export_to_txt(scan_results, file_path)
        self.status_lbl.setText(f"نتایج با موفقیت در فایل {file_path} ذخیره شد.")
