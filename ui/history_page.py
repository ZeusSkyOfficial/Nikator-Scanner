"""History module page for Nikator Scanner.
Loads historical scan sessions from SQLite, allows filtering, inspection, deletion, and export.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database.history import HistoryManager
from models.results import ScanResult
from ui.dialogs import ConfirmDialog, ResultDetailsDialog
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import CircularStatusIndicator, ToastNotification
from utils.exporters import export_to_csv, export_to_json, export_to_txt


class HistoryPage(QWidget):
    """Scan history page backed by SQLite database."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.history_mgr = HistoryManager()
        self.sessions: List[Dict[str, Any]] = []
        self.current_results: List[ScanResult] = []

        self._init_ui()
        self.refresh_sessions()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        title_lbl = QLabel("تاریخچه اسکن")
        title_lbl.setStyleSheet("font-size: 22px; font-weight: 800; color: #FFFFFF;")
        sub_lbl = QLabel("بررسی، بازپخش و استخراج گزارش‌ها و نشست‌های تشخیصی گذشته")
        sub_lbl.setStyleSheet(f"font-size: 13px; color: {Colors.DARK_TEXT_SECONDARY};")
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(sub_lbl)
        layout.addLayout(header_layout)

        # Toolbar: Search, Refresh, Clear All
        toolbar_frame = QFrame()
        toolbar_frame.setProperty("class", "CardFrame")
        tb_layout = QHBoxLayout(toolbar_frame)
        tb_layout.setContentsMargins(10, 8, 10, 8)
        tb_layout.setSpacing(10)

        s_icon = QLabel()
        s_icon.setPixmap(get_pixmap("search", color=Colors.DARK_TEXT_MUTED, size=16))
        tb_layout.addWidget(s_icon)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("جستجو در نشست‌های گذشته بر اساس دامنه یا نوع اسکن...")
        self.search_input.textChanged.connect(self.refresh_sessions)
        tb_layout.addWidget(self.search_input, stretch=2)

        refresh_btn = QPushButton("بروزرسانی")
        refresh_btn.setIcon(get_icon("refresh", color=Colors.NEON_BLUE, size=14))
        refresh_btn.clicked.connect(self.refresh_sessions)
        tb_layout.addWidget(refresh_btn)

        clear_all_btn = QPushButton("پاکسازی کل تاریخچه")
        clear_all_btn.setIcon(get_icon("trash", color=Colors.FAILED_RED, size=14))
        clear_all_btn.clicked.connect(self._clear_all_history)
        tb_layout.addWidget(clear_all_btn)

        layout.addWidget(toolbar_frame)

        # Splitter: Upper Session List, Lower Results Table
        splitter = QSplitter(Qt.Vertical)

        # Sessions Table
        sess_container = QWidget()
        sess_layout = QVBoxLayout(sess_container)
        sess_layout.setContentsMargins(0, 0, 0, 0)
        sess_layout.setSpacing(6)

        sess_title = QLabel("نشست‌های ثبت‌شده عیب‌یابی:")
        sess_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        sess_layout.addWidget(sess_title)

        self.session_table = QTableWidget()
        self.session_table.setColumnCount(8)
        self.session_table.setHorizontalHeaderLabels([
            "زمان شروع",
            "نوع اسکن",
            "هدف ورودی",
            "تعداد کل",
            "موفق",
            "ناموفق",
            "میانگین تاخیر",
            "عملیات",
        ])

        header = self.session_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.session_table.setColumnWidth(0, 160)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        self.session_table.setColumnWidth(1, 130)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.session_table.setColumnWidth(3, 80)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.session_table.setColumnWidth(4, 80)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.session_table.setColumnWidth(5, 80)
        header.setSectionResizeMode(6, QHeaderView.Interactive)
        self.session_table.setColumnWidth(6, 110)
        header.setSectionResizeMode(7, QHeaderView.Fixed)
        self.session_table.setColumnWidth(7, 170)

        self.session_table.verticalHeader().setVisible(False)
        self.session_table.verticalHeader().setDefaultSectionSize(40)
        self.session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.session_table.itemSelectionChanged.connect(self._on_session_selected)
        sess_layout.addWidget(self.session_table)
        splitter.addWidget(sess_container)

        # Details / Results for selected session
        res_container = QWidget()
        res_layout = QVBoxLayout(res_container)
        res_layout.setContentsMargins(0, 6, 0, 0)
        res_layout.setSpacing(6)

        res_header = QHBoxLayout()
        self.res_title = QLabel("نتایج نشست (یک مورد را از بالا انتخاب کنید):")
        self.res_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        res_header.addWidget(self.res_title)
        res_header.addStretch()

        self.exp_btn = QPushButton("استخراج نتایج نشست...")
        self.exp_btn.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=14))
        self.exp_btn.setEnabled(False)
        self.exp_btn.clicked.connect(self._export_selected_session)
        res_header.addWidget(self.exp_btn)
        res_layout.addLayout(res_header)

        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "نام میزبان",
            "آدرس آی‌پی",
            "پورت",
            "اس‌ان‌آی (SNI)",
            "وضعیت",
            "تاخیر",
            "موضوع گواهی",
            "زمان ثبت",
        ])

        r_hdr = self.results_table.horizontalHeader()
        r_hdr.setSectionResizeMode(0, QHeaderView.Stretch)
        r_hdr.setSectionResizeMode(1, QHeaderView.Interactive)
        self.results_table.setColumnWidth(1, 130)
        r_hdr.setSectionResizeMode(2, QHeaderView.Fixed)
        self.results_table.setColumnWidth(2, 55)
        r_hdr.setSectionResizeMode(3, QHeaderView.Interactive)
        self.results_table.setColumnWidth(3, 140)
        r_hdr.setSectionResizeMode(4, QHeaderView.Fixed)
        self.results_table.setColumnWidth(4, 90)
        r_hdr.setSectionResizeMode(5, QHeaderView.Interactive)
        self.results_table.setColumnWidth(5, 80)
        r_hdr.setSectionResizeMode(6, QHeaderView.Stretch)
        r_hdr.setSectionResizeMode(7, QHeaderView.Interactive)
        self.results_table.setColumnWidth(7, 130)

        self.results_table.verticalHeader().setVisible(False)
        self.results_table.verticalHeader().setDefaultSectionSize(38)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.itemDoubleClicked.connect(self._on_result_double_clicked)
        res_layout.addWidget(self.results_table)

        splitter.addWidget(res_container)
        splitter.setSizes([260, 360])

        layout.addWidget(splitter)

    def refresh_sessions(self) -> None:
        """Fetch sessions from SQLite database and populate table."""
        query = self.search_input.text().strip()
        self.sessions = self.history_mgr.get_sessions(search=query, limit=100)

        self.session_table.setRowCount(len(self.sessions))
        for row, s in enumerate(self.sessions):
            # 0: Date
            started = s.get("started_at", "").replace("T", " ")[:19]
            self.session_table.setItem(row, 0, QTableWidgetItem(started))

            # 1: Scan Type
            scan_type = s.get("scan_type", "اسکن")
            type_map = {
                "sni_scan": "اسکن SNI",
                "config_test": "تست کانفیگ",
                "ip_test": "تست آی‌پی",
                "sni_compatibility": "سازگاری SNI",
                "Scan": "اسکن کلی",
            }
            display_type = type_map.get(scan_type, scan_type)
            self.session_table.setItem(row, 1, QTableWidgetItem(display_type))

            # 2: Target Input
            tgt_item = QTableWidgetItem(s.get("target_domain", ""))
            tgt_item.setForeground(QColor("#FFFFFF"))
            tgt_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.session_table.setItem(row, 2, tgt_item)

            # 3: Total
            self.session_table.setItem(row, 3, QTableWidgetItem(str(s.get("total_tested", 0))))

            # 4: Success
            succ_item = QTableWidgetItem(str(s.get("successful_count", 0)))
            succ_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            self.session_table.setItem(row, 4, succ_item)

            # 5: Failed
            fail_item = QTableWidgetItem(str(s.get("failed_count", 0)))
            fail_item.setForeground(QColor(Colors.FAILED_RED))
            self.session_table.setItem(row, 5, fail_item)

            # 6: Latency
            lat = s.get("avg_latency_ms", 0.0)
            self.session_table.setItem(row, 6, QTableWidgetItem(f"{lat:.1f} میلی‌ثانیه" if lat else "نامشخص"))

            # 7: Actions (Open & Delete Buttons)
            sess_id = s.get("session_id", "")
            act_box = QWidget()
            act_lay = QHBoxLayout(act_box)
            act_lay.setContentsMargins(4, 2, 4, 2)
            act_lay.setSpacing(6)
            act_lay.setAlignment(Qt.AlignCenter)

            open_btn = QPushButton("مشاهده")
            open_btn.setIcon(get_icon("search", color=Colors.NEON_BLUE, size=12))
            open_btn.setFixedSize(72, 28)
            open_btn.setCursor(Qt.PointingHandCursor)
            open_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(0, 212, 255, 0.12);
                    color: #00d4ff;
                    border: 1px solid rgba(0, 212, 255, 0.4);
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
            open_btn.clicked.connect(lambda _, sid=sess_id: self._load_session_results(sid))
            act_lay.addWidget(open_btn)

            del_btn = QPushButton("حذف")
            del_btn.setIcon(get_icon("trash", color=Colors.FAILED_RED, size=12))
            del_btn.setFixedSize(62, 28)
            del_btn.setCursor(Qt.PointingHandCursor)
            del_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(255, 59, 48, 0.12);
                    color: #ff453a;
                    border: 1px solid rgba(255, 59, 48, 0.4);
                    border-radius: 4px;
                    padding: 0px 4px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: rgba(255, 59, 48, 0.25);
                    border: 1px solid #ff453a;
                }
            """)
            del_btn.clicked.connect(lambda _, sid=sess_id: self._delete_session(sid))
            act_lay.addWidget(del_btn)

            self.session_table.setCellWidget(row, 7, act_box)

    def _on_session_selected(self) -> None:
        rows = self.session_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if 0 <= row < len(self.sessions):
            sess_id = self.sessions[row]["session_id"]
            self._load_session_results(sess_id)

    def _load_session_results(self, session_id: str) -> None:
        self.current_results = self.history_mgr.get_session_results(session_id)
        self.exp_btn.setEnabled(bool(self.current_results))
        self.res_title.setText(f"نتایج نشست ({len(self.current_results)} مورد ثبت‌شده):")

        self.results_table.setRowCount(len(self.current_results))
        for row, r in enumerate(self.current_results):
            # 0: Hostname
            h_item = QTableWidgetItem(r.target.hostname)
            h_item.setForeground(QColor("#FFFFFF"))
            self.results_table.setItem(row, 0, h_item)

            # 1: IP
            ip_item = QTableWidgetItem(r.display_ip)
            ip_item.setForeground(QColor(Colors.NEON_BLUE))
            self.results_table.setItem(row, 1, ip_item)

            # 2: Port
            self.results_table.setItem(row, 2, QTableWidgetItem(str(r.target.port)))

            # 3: SNI
            self.results_table.setItem(row, 3, QTableWidgetItem(r.target.sni))

            # 4: Status
            status_labels = {
                "success": "موفق",
                "partial": "هشدار/جزئی",
                "failed": "ناموفق",
                "timeout": "تایم‌اوت",
                "error": "خطا",
            }
            lbl = status_labels.get(r.status.value, r.status.label)
            stat_item = QTableWidgetItem(lbl)
            if r.status.value == "success":
                stat_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            elif r.status.value == "partial":
                stat_item.setForeground(QColor(Colors.WARNING_AMBER))
            else:
                stat_item.setForeground(QColor(Colors.FAILED_RED))
            self.results_table.setItem(row, 4, stat_item)

            # 5: Latency
            lat_str = f"{r.total_latency_ms:.1f} میلی‌ثانیه" if r.total_latency_ms else "نامشخص"
            self.results_table.setItem(row, 5, QTableWidgetItem(lat_str))

            # 6: Certificate Subject
            self.results_table.setItem(row, 6, QTableWidgetItem(r.tls.certificate.subject or r.tls.error or "ندارد"))

            # 7: Timestamp
            self.results_table.setItem(row, 7, QTableWidgetItem(r.timestamp.replace("T", " ")[:19]))

    def _on_result_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        if 0 <= row < len(self.current_results):
            res = self.current_results[row]
            dlg = ResultDetailsDialog(res, self)
            dlg.exec()

    def _delete_session(self, session_id: str) -> None:
        dlg = ConfirmDialog(
            "حذف نشست",
            "آیا مطمئن هستید که می‌خواهید این نشست اسکن را برای همیشه حذف کنید؟",
            confirm_label="حذف برای همیشه",
            is_danger=True,
            parent=self,
        )
        if dlg.exec() == ConfirmDialog.Accepted:
            self.history_mgr.delete_session(session_id)
            self.refresh_sessions()
            self.results_table.setRowCount(0)
            self.current_results.clear()
            self.exp_btn.setEnabled(False)
            ToastNotification("نشست اسکن با موفقیت حذف شد", self)

    def _clear_all_history(self) -> None:
        dlg = ConfirmDialog(
            "پاکسازی کل تاریخچه",
            "آیا مطمئن هستید که می‌خواهید تمام تاریخچه و گزارش‌های ثبت‌شده عیب‌یابی را پاک کنید؟ این عملیات غیرقابل بازگشت است.",
            confirm_label="پاکسازی همه",
            is_danger=True,
            parent=self,
        )
        if dlg.exec() == ConfirmDialog.Accepted:
            self.history_mgr.clear_all()
            self.refresh_sessions()
            self.results_table.setRowCount(0)
            self.current_results.clear()
            self.exp_btn.setEnabled(False)
            ToastNotification("تمام تاریخچه اسکن‌ها پاکسازی شد", self)

    def _export_selected_session(self) -> None:
        if not self.current_results:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "استخراج نتایج نشست",
            "session_results.csv",
            "فایل‌های CSV (*.csv);;فایل‌های JSON (*.json);;فایل‌های متنی (*.txt)",
        )
        if file_path:
            if file_path.endswith(".json"):
                export_to_json(self.current_results, file_path)
            elif file_path.endswith(".txt"):
                export_to_txt(self.current_results, file_path)
            else:
                export_to_csv(self.current_results, file_path)
            ToastNotification("نتایج نشست با موفقیت استخراج شد", self)
