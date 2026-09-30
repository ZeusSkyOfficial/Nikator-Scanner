"""SNI Compatibility Research module for Nikator Scanner.
Researches standard TLS SNI behavior, Certificate Match/Mismatch, and HTTPS negotiation.
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import QPoint, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
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
    QRadioButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models.results import ApplicationSettings, ScanResult, ScanStatus, ScanTarget
from scanners.compatibility_scanner import CompatibilityScanner
from ui.dialogs import ResultDetailsDialog
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import CircularStatusIndicator, ToastNotification
from utils.clipboard import copy_text_to_clipboard
from utils.exporters import export_to_csv, export_to_json, export_to_txt


class CompatWorkerThread(QThread):
    progress_signal = Signal(int, int, str)
    result_signal = Signal(object)
    finished_signal = Signal()

    def __init__(
        self,
        scanner: CompatibilityScanner,
        target_endpoint: str,
        sni_list: List[str],
        port: int = 443,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.scanner = scanner
        self.target_endpoint = target_endpoint
        self.sni_list = sni_list
        self.port = port

    def run(self) -> None:
        def on_prog(tested: int, total: int, msg: str) -> None:
            self.progress_signal.emit(tested, total, msg)

        def on_res(res: ScanResult) -> None:
            self.result_signal.emit(res)

        self.scanner.scan_compatibility(
            target_ip_or_host=self.target_endpoint,
            sni_list=self.sni_list,
            port=self.port,
            progress_callback=on_prog,
            result_callback=on_res,
        )
        self.finished_signal.emit()


class CompatibilityPage(QWidget):
    """SNI Compatibility Research page."""

    def __init__(self, settings: ApplicationSettings, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.scanner = CompatibilityScanner(settings)
        self.worker: Optional[CompatWorkerThread] = None
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
        title_lbl = QLabel("سازگاری و انطباق SNI")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF;")
        sub_lbl = QLabel("بررسی رفتار سرور در برابر تغییر مقادیر SNI و تشخیص تطابق یا عدم تطابق گواهی")
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

        # Left Card: Target & SNI Mode
        in_frame = QFrame()
        in_frame.setProperty("class", "CardFrame")
        in_layout = QVBoxLayout(in_frame)
        in_layout.setContentsMargins(14, 12, 14, 12)
        in_layout.setSpacing(8)

        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("آدرس هاست / IP هدف:"))
        self.target_input = QLineEdit()
        self.target_input.setFixedHeight(34)
        self.target_input.setPlaceholderText("1.1.1.1 یا cloudflare.com")
        self.target_input.setText("1.1.1.1")
        target_row.addWidget(self.target_input, stretch=2)

        target_row.addWidget(QLabel("پورت:"))
        self.port_spin = QSpinBox()
        self.port_spin.setFixedHeight(34)
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(443)
        target_row.addWidget(self.port_spin)
        in_layout.addLayout(target_row)

        # Radio Mode Selector
        mode_box = QHBoxLayout()
        self.radio_mode_b = QRadioButton("حالت اول — لیست عمومی دامنه‌ها")
        self.radio_mode_b.setChecked(True)
        self.radio_mode_b.toggled.connect(self._on_mode_toggled)

        self.radio_mode_a = QRadioButton("حالت دوم — لیست سفارشی کاربر")
        self.radio_mode_a.toggled.connect(self._on_mode_toggled)

        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.radio_mode_b)
        self.mode_group.addButton(self.radio_mode_a)

        mode_box.addWidget(self.radio_mode_b)
        mode_box.addWidget(self.radio_mode_a)
        mode_box.addStretch()
        in_layout.addLayout(mode_box)

        # Mode A User Input area
        self.user_sni_input = QPlainTextEdit()
        self.user_sni_input.setPlaceholderText("دامنه‌های SNI مورد نظر را وارد کنید (هر خط یک دامنه)...\nexample.com\ncloudflare.com\ngoogle.com")
        self.user_sni_input.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        self.user_sni_input.setVisible(False)
        in_layout.addWidget(self.user_sni_input)

        # Mode B Public Count selector
        self.public_row = QHBoxLayout()
        self.public_row.addWidget(QLabel("تعداد کاندیداهای عمومی:"))
        self.public_count_spin = QSpinBox()
        self.public_count_spin.setFixedHeight(34)
        self.public_count_spin.setRange(5, 500)
        self.public_count_spin.setValue(30)
        self.public_row.addWidget(self.public_count_spin)
        self.public_row.addStretch()
        in_layout.addLayout(self.public_row)

        top_layout.addWidget(in_frame, stretch=3)

        # Right Card: Actions
        ctrl_frame = QFrame()
        ctrl_frame.setProperty("class", "CardFrame")
        ctrl_frame.setFixedWidth(270)
        c_layout = QVBoxLayout(ctrl_frame)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        c_title = QLabel("کنترل پژوهش و بررسی")
        c_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        c_layout.addWidget(c_title)

        c_desc = QLabel("آزمایش پذیرش هدر SNI، نسخه پروتکل TLS، نام مشترک (CN) گواهی و پوشش دامنه‌های SAN سرور.")
        c_desc.setWordWrap(True)
        c_desc.setStyleSheet(f"font-size: 11px; color: {Colors.DARK_TEXT_SECONDARY};")
        c_layout.addWidget(c_desc)

        c_layout.addStretch()

        self.start_btn = QPushButton("شروع پژوهش سازگاری")
        self.start_btn.setProperty("class", "PrimaryBtn")
        self.start_btn.setFixedHeight(38)
        self.start_btn.setIcon(get_icon("play", color="#FFFFFF", size=16))
        self.start_btn.clicked.connect(self.start_research)
        c_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("توقف")
        self.stop_btn.setProperty("class", "DangerBtn")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.setIcon(get_icon("stop", color="#FFFFFF", size=14))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_research)
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
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels([
            "هدف / هاست",
            "SNI تست‌شده",
            "TCP",
            "هندشیک TLS",
            "نسخه TLS",
            "الگوریتم Cipher",
            "رفتار سازگاری SNI",
            "کد HTTP",
            "پینگ",
            "موضوع گواهی (Subject)",
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.table.setColumnWidth(0, 130)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        self.table.setColumnWidth(1, 160)
        header.setSectionResizeMode(2, QHeaderView.Fixed)
        self.table.setColumnWidth(2, 45)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.table.setColumnWidth(3, 90)
        header.setSectionResizeMode(4, QHeaderView.Interactive)
        self.table.setColumnWidth(4, 80)
        header.setSectionResizeMode(5, QHeaderView.Interactive)
        self.table.setColumnWidth(5, 120)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        self.table.setColumnWidth(7, 80)
        header.setSectionResizeMode(8, QHeaderView.Interactive)
        self.table.setColumnWidth(8, 75)
        header.setSectionResizeMode(9, QHeaderView.Stretch)

        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.itemDoubleClicked.connect(self._on_double_clicked)
        b_layout.addWidget(self.table)

        # Export row
        exp_row = QHBoxLayout()

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
        splitter.setSizes([240, 400])

        layout.addWidget(splitter)

    def _on_mode_toggled(self) -> None:
        is_mode_a = self.radio_mode_a.isChecked()
        self.user_sni_input.setVisible(is_mode_a)
        self.public_count_spin.setVisible(not is_mode_a)

    def start_research(self) -> None:
        target_endpoint = self.target_input.text().strip()
        if not target_endpoint:
            self.status_lbl.setText("وارد کردن آدرس IP یا هاست هدف الزامی است")
            return

        port = self.port_spin.value()
        sni_list: List[str] = []

        if self.radio_mode_a.isChecked():
            raw = self.user_sni_input.toPlainText().strip()
            sni_list = [l.strip() for l in raw.splitlines() if l.strip()]
            if not sni_list:
                self.status_lbl.setText("حداقل یک دامنه SNI باید وارد شود")
                return
        else:
            limit = self.public_count_spin.value()
            sni_list = self.scanner.get_public_sni_candidates(limit=limit)

        self.results.clear()
        self.table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        self.worker = CompatWorkerThread(
            scanner=self.scanner,
            target_endpoint=target_endpoint,
            sni_list=sni_list,
            port=port,
            parent=self,
        )
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.result_signal.connect(self._on_result)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def stop_research(self) -> None:
        if self.worker and self.worker.isRunning():
            self.scanner.cancel()
            self.worker.wait(1000)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("پژوهش متوقف شد")

    def _on_progress(self, tested: int, total: int, msg: str) -> None:
        pct = int((tested / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.status_lbl.setText(f"در حال بررسی {tested}/{total}: {msg}")

    def _on_result(self, res: ScanResult) -> None:
        self.results.append(res)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 0: Target
        self.table.setItem(row, 0, QTableWidgetItem(f"{res.target.hostname}:{res.target.port}"))

        # 1: SNI
        sni_item = QTableWidgetItem(res.target.sni)
        sni_item.setForeground(QColor(Colors.NEON_BLUE))
        self.table.setItem(row, 1, sni_item)

        # 2: TCP
        tcp_state = "success" if res.tcp.connected else "failed"
        self.table.setCellWidget(row, 2, self._wrap_ind(CircularStatusIndicator(tcp_state, 16)))

        # 3: TLS Handshake
        tls_state = "success" if res.tls.handshake_success else "failed"
        self.table.setCellWidget(row, 3, self._wrap_ind(CircularStatusIndicator(tls_state, 16)))

        # 4: TLS Version
        self.table.setItem(row, 4, QTableWidgetItem(res.tls.tls_version or "–"))

        # 5: Cipher
        self.table.setItem(row, 5, QTableWidgetItem(res.tls.cipher or "–"))

        # 6: Compatibility Behavior
        behavior_text = res.notes
        if "Certificate Match" in behavior_text:
            display_text = "تطابق کامل با گواهی سرور"
            text_color = Colors.SUCCESS_GREEN
        elif "Certificate Mismatch" in behavior_text:
            display_text = "عدم انطباق گواهی با SNI (SNI Mismatch)"
            text_color = Colors.WARNING_AMBER
        else:
            display_text = behavior_text or "ناموفق"
            text_color = Colors.FAILED_RED

        behavior_item = QTableWidgetItem(display_text)
        behavior_item.setForeground(QColor(text_color))
        behavior_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.table.setItem(row, 6, behavior_item)

        # 7: HTTP Status
        http_val = str(res.http.status_code) if res.http.status_code > 0 else "–"
        self.table.setItem(row, 7, QTableWidgetItem(http_val))

        # 8: Latency
        self.table.setItem(row, 8, QTableWidgetItem(res.display_latency))

        # 9: Certificate Subject
        self.table.setItem(row, 9, QTableWidgetItem(res.tls.certificate.subject or res.tls.error or "ندارد"))

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
        self.status_lbl.setText("پژوهش سازگاری SNI پایان یافت")

    def _clear_results(self) -> None:
        self.results.clear()
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.status_lbl.setText("آماده")

    def _on_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self.results):
            res = self.results[row]
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _show_context_menu(self, pos: QPoint) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.results):
            return

        res = self.results[row]
        menu = QMenu(self)
        c_sni = menu.addAction(f"کپی هدر SNI: {res.target.sni}")
        c_tgt = menu.addAction(f"کپی هاست هدف: {res.target.hostname}")
        menu.addSeparator()
        view_action = menu.addAction("مشاهده جزئیات کامل عیب‌یابی...")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == c_sni:
            copy_text_to_clipboard(res.target.sni or "")
        elif action == c_tgt:
            copy_text_to_clipboard(res.target.hostname)
        elif action == view_action:
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _export_results(self, fmt: str) -> None:
        if not self.results:
            return

        fmt = fmt.lower()
        file_path, _ = QFileDialog.getSaveFileName(self, f"خروجی به فرمت {fmt.upper()}", f"sni_compatibility.{fmt}", f"فایل‌های {fmt.upper()} (*.{fmt})")
        if not file_path:
            return

        if fmt == "json":
            export_to_json(self.results, file_path)
        elif fmt == "csv":
            export_to_csv(self.results, file_path)
        elif fmt == "txt":
            export_to_txt(self.results, file_path)
