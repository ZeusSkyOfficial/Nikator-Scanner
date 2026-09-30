"""IP Tester module page for Nikator Scanner.
Allows pasting IP lists or importing TXT/CSV to test TCP/TLS reachability from current network.
"""

from __future__ import annotations

from typing import List, Optional

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

from models.results import ApplicationSettings, ScanResult, ScanStatus, ScanTarget
from scanners.ip_scanner import IPScanner
from ui.dialogs import ResultDetailsDialog
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import CircularStatusIndicator, ToastNotification
from utils.clipboard import copy_text_to_clipboard
from utils.exporters import export_to_csv, export_to_json, export_to_txt
from utils.validation import is_valid_ip


class IPWorkerThread(QThread):
    progress_signal = Signal(int, int, str)
    result_signal = Signal(object)
    finished_signal = Signal()

    def __init__(
        self,
        scanner: IPScanner,
        ip_list: List[str],
        port: int = 443,
        test_tls: bool = True,
        sni: Optional[str] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.scanner = scanner
        self.ip_list = ip_list
        self.port = port
        self.test_tls = test_tls
        self.sni = sni

    def run(self) -> None:
        def on_prog(tested: int, total: int, msg: str) -> None:
            self.progress_signal.emit(tested, total, msg)

        def on_res(res: ScanResult) -> None:
            self.result_signal.emit(res)

        self.scanner.scan_ips(
            ip_list=self.ip_list,
            port=self.port,
            test_tls=self.test_tls,
            sni=self.sni,
            progress_callback=on_prog,
            result_callback=on_res,
        )
        self.finished_signal.emit()


class IPTesterPage(QWidget):
    """IP Tester diagnostic page."""

    def __init__(self, settings: ApplicationSettings, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.scanner = IPScanner(settings)
        self.worker: Optional[IPWorkerThread] = None
        self.results: List[ScanResult] = []

        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(10)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)
        title_lbl = QLabel("تست‌کننده آی‌پی")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF;")
        sub_lbl = QLabel("بررسی مستقیم سلامت و دسترسی‌پذیری آدرس‌های IP از شبکه فعلی شما")
        sub_lbl.setStyleSheet(f"font-size: 12px; color: {Colors.DARK_TEXT_SECONDARY};")
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(sub_lbl)
        layout.addLayout(header_layout)

        # Splitter: Input / Settings (Top) and Results Table (Bottom)
        splitter = QSplitter(Qt.Vertical)

        # Top Section
        top_widget = QWidget()
        top_layout = QHBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(12)

        # Left: Paste IP List
        input_frame = QFrame()
        input_frame.setProperty("class", "CardFrame")
        in_layout = QVBoxLayout(input_frame)
        in_layout.setContentsMargins(12, 10, 12, 10)
        in_layout.setSpacing(6)

        in_header = QHBoxLayout()
        in_title = QLabel("آدرس‌های آی‌پی (هر خط یک آی‌پی):")
        in_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        in_header.addWidget(in_title)
        in_header.addStretch()

        import_btn = QPushButton("وارد کردن TXT / CSV...")
        import_btn.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=14))
        import_btn.clicked.connect(self._import_ips)
        in_header.addWidget(import_btn)
        in_layout.addLayout(in_header)

        self.ip_input = QPlainTextEdit()
        self.ip_input.setPlaceholderText(
            "آدرس‌های IP مورد نظر خود را اینجا وارد کنید (هر سطر یک IP)\n"
            "مثال:\n"
            "1.1.1.1\n"
            "8.8.8.8\n"
            "104.16.132.229\n"
            "142.250.190.46"
        )
        self.ip_input.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        # No default IPs per user request!
        self.ip_input.setPlainText("")
        in_layout.addWidget(self.ip_input)

        top_layout.addWidget(input_frame, stretch=3)

        # Right: Parameters
        ctrl_frame = QFrame()
        ctrl_frame.setProperty("class", "CardFrame")
        ctrl_frame.setFixedWidth(290)
        c_layout = QVBoxLayout(ctrl_frame)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        ctrl_title = QLabel("پارامترهای کاوش")
        ctrl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        c_layout.addWidget(ctrl_title)

        # Port
        c_layout.addWidget(QLabel("پورت هدف:"))
        self.port_spin = QSpinBox()
        self.port_spin.setFixedHeight(34)
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(443)
        c_layout.addWidget(self.port_spin)

        # Protocol / TLS toggle
        self.tls_chk = QCheckBox("انجام هندشیک TLS")
        self.tls_chk.setChecked(True)
        c_layout.addWidget(self.tls_chk)

        # Optional SNI for TLS
        c_layout.addWidget(QLabel("SNI اختیاری برای TLS:"))
        self.sni_input = QLineEdit()
        self.sni_input.setFixedHeight(34)
        self.sni_input.setPlaceholderText("cloudflare.com (اختیاری)")
        c_layout.addWidget(self.sni_input)

        # Timeout
        c_layout.addWidget(QLabel("تایم‌اوت (ثانیه):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setFixedHeight(34)
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(int(self.settings.tcp_timeout))
        c_layout.addWidget(self.timeout_spin)

        c_layout.addStretch()

        # Start / Stop Buttons
        self.start_btn = QPushButton("بررسی دسترسی‌پذیری IPها")
        self.start_btn.setProperty("class", "PrimaryBtn")
        self.start_btn.setFixedHeight(38)
        self.start_btn.setIcon(get_icon("play", color="#FFFFFF", size=16))
        self.start_btn.clicked.connect(self.start_scan)
        c_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("توقف")
        self.stop_btn.setProperty("class", "DangerBtn")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.setIcon(get_icon("stop", color="#FFFFFF", size=14))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        c_layout.addWidget(self.stop_btn)

        top_layout.addWidget(ctrl_frame, stretch=1)
        splitter.addWidget(top_widget)

        # Bottom Section: Results Table
        bottom_widget = QWidget()
        b_layout = QVBoxLayout(bottom_widget)
        b_layout.setContentsMargins(0, 8, 0, 0)
        b_layout.setSpacing(8)

        # Progress bar
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
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "آدرس IP",
            "پورت",
            "دسترسی از اینترنت شما",
            "وضعیت TCP",
            "وضعیت TLS",
            "پینگ",
            "خطا / توضیحات",
            "زمان",
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.setColumnWidth(0, 160)
        header.setSectionResizeMode(1, QHeaderView.Fixed)
        self.table.setColumnWidth(1, 60)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(3, 70)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.table.setColumnWidth(4, 70)
        header.setSectionResizeMode(5, QHeaderView.Interactive)
        self.table.setColumnWidth(5, 90)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Interactive)
        self.table.setColumnWidth(7, 100)

        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemDoubleClicked.connect(self._on_double_clicked)
        b_layout.addWidget(self.table)

        # Export row
        exp_row = QHBoxLayout()

        copy_reachable_btn = QPushButton("کپی IPهای در دسترس")
        copy_reachable_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=12))
        copy_reachable_btn.clicked.connect(self._copy_reachable_ips)
        exp_row.addWidget(copy_reachable_btn)

        clear_btn = QPushButton("پاکسازی نتایج")
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

    def _import_ips(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "وارد کردن لیست IP", "", "فایل‌های متنی (*.txt *.csv);;همه فایل‌ها (*.*)")
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
                self.ip_input.setPlainText("\n".join(lines))
            except Exception:
                pass

    def start_scan(self) -> None:
        text = self.ip_input.toPlainText().strip()
        lines = [line.strip().split(",")[0].split(":")[0] for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        valid_ips = [ip for ip in lines if is_valid_ip(ip)]

        if not valid_ips:
            self.status_lbl.setText("هیچ آدرس IP معتبری در کادر وارد نشده است")
            return

        self.results.clear()
        self.table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        port = self.port_spin.value()
        test_tls = self.tls_chk.isChecked()
        sni = self.sni_input.text().strip() or None

        self.scanner.settings.tcp_timeout = float(self.timeout_spin.value())
        self.scanner.settings.tls_timeout = float(self.timeout_spin.value())

        self.worker = IPWorkerThread(
            scanner=self.scanner,
            ip_list=valid_ips,
            port=port,
            test_tls=test_tls,
            sni=sni,
            parent=self,
        )
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.result_signal.connect(self._on_result)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def stop_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            self.scanner.cancel()
            self.worker.wait(1000)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("عملیات متوقف شد")

    def _on_progress(self, tested: int, total: int, msg: str) -> None:
        pct = int((tested / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_lbl.setText(f"{tested}/{total}: {msg}")

    def _on_result(self, res: ScanResult) -> None:
        self.results.append(res)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 0: IP
        ip_item = QTableWidgetItem(res.target.ip)
        ip_item.setForeground(QColor(Colors.NEON_BLUE))
        self.table.setItem(row, 0, ip_item)

        # 1: Port
        self.table.setItem(row, 1, QTableWidgetItem(str(res.target.port)))

        # 2: Reachability Statement
        reach_lbl = "قابل دسترسی از اینترنت فعلی" if res.tcp.connected else "غیرقابل دسترسی از اینترنت فعلی"
        reach_item = QTableWidgetItem(reach_lbl)
        reach_color = Colors.SUCCESS_GREEN if res.tcp.connected else Colors.FAILED_RED
        reach_item.setForeground(QColor(reach_color))
        reach_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.table.setItem(row, 2, reach_item)

        # 3: TCP
        tcp_state = "success" if res.tcp.connected else "failed"
        self.table.setCellWidget(row, 3, self._wrap_ind(CircularStatusIndicator(tcp_state, 16)))

        # 4: TLS
        if self.tls_chk.isChecked():
            tls_state = "success" if res.tls.handshake_success else ("failed" if res.tcp.connected else "none")
        else:
            tls_state = "none"
        self.table.setCellWidget(row, 4, self._wrap_ind(CircularStatusIndicator(tls_state, 16)))

        # 5: Latency
        self.table.setItem(row, 5, QTableWidgetItem(res.display_latency))

        # 6: Error
        err_msg = res.tls.error or res.tcp.error or ""
        err_item = QTableWidgetItem(err_msg)
        err_item.setForeground(QColor(Colors.FAILED_RED if err_msg else Colors.DARK_TEXT_MUTED))
        self.table.setItem(row, 6, err_item)

        # 7: Timestamp
        self.table.setItem(row, 7, QTableWidgetItem(res.timestamp.split("T")[-1][:8]))

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
        self.status_lbl.setText("بررسی دسترسی‌پذیری IPها پایان یافت")

    def _on_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self.results):
            res = self.results[row]
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _copy_reachable_ips(self) -> None:
        reachable = [r.target.ip for r in self.results if r.tcp.connected and r.target.ip]
        if reachable:
            copy_text_to_clipboard("\n".join(reachable))

    def _clear_results(self) -> None:
        self.results.clear()
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_lbl.setText("آماده")

    def _show_context_menu(self, pos: QPoint) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results):
            return

        res = self.results[row]
        menu = QMenu(self)
        c_ip = menu.addAction(f"کپی آی‌پی: {res.target.ip}")
        c_port = menu.addAction(f"کپی پورت: {res.target.port}")
        menu.addSeparator()
        view_action = menu.addAction("مشاهده جزئیات کامل عیب‌یابی...")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == c_ip:
            copy_text_to_clipboard(res.target.ip or "")
        elif action == c_port:
            copy_text_to_clipboard(str(res.target.port))
        elif action == view_action:
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _export_results(self, fmt: str) -> None:
        if not self.results:
            return

        fmt = fmt.lower()
        file_path, _ = QFileDialog.getSaveFileName(self, f"خروجی به فرمت {fmt.upper()}", f"ip_reachability.{fmt}", f"فایل‌های {fmt.upper()} (*.{fmt})")
        if not file_path:
            return

        if fmt == "json":
            export_to_json(self.results, file_path)
        elif fmt == "csv":
            export_to_csv(self.results, file_path)
        elif fmt == "txt":
            export_to_txt(self.results, file_path)
