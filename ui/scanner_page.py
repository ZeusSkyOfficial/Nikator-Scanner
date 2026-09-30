"""SNI Scanner dashboard page for Nikator Scanner.
Features dynamic stats cards, configuration controls, interactive results table,
live diagnostic details panel, search/filter toolbar, and quick actions.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PySide6.QtCore import QPoint, QSize, Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QCursor, QFont, QIcon, QKeySequence, QShortcut
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
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from database.history import HistoryManager
from models.results import ApplicationSettings, ScanResult, ScanSession, ScanStatus, ScanTarget
from scanners.sni_scanner import SNIScanner
from ui.dialogs import ConfirmDialog, ResultDetailsDialog
from ui.icons import get_icon, get_pixmap
from ui.theme import Colors
from ui.widgets import CircularStatusIndicator, StatCard, ToastNotification
from utils.clipboard import copy_text_to_clipboard
from utils.exporters import export_to_csv, export_to_json, export_to_txt
from utils.validation import is_valid_domain, normalize_domain


class ScannerWorkerThread(QThread):
    """Background worker thread executing multi-stage diagnostics without blocking GUI."""

    progress_signal = Signal(int, int, str)
    result_signal = Signal(object)
    finished_signal = Signal(object, list)

    def __init__(
        self,
        scanner: SNIScanner,
        targets: List[ScanTarget],
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.scanner = scanner
        self.targets = targets

    def run(self) -> None:
        def on_prog(tested: int, total: int, op: str) -> None:
            self.progress_signal.emit(tested, total, op)

        def on_res(res: ScanResult) -> None:
            self.result_signal.emit(res)

        def on_finish(sess: ScanSession, res_list: List[ScanResult]) -> None:
            self.finished_signal.emit(sess, res_list)

        self.scanner.scan_targets(
            targets=self.targets,
            progress_callback=on_prog,
            result_callback=on_res,
            batch_finished_callback=on_finish,
        )


class ScannerPage(QWidget):
    """Primary SNI Scanner and network diagnostic view."""

    status_updated = Signal(str, str, int, int, int, float)  # state, current_op, tested, total, success, latency

    def __init__(self, settings: ApplicationSettings, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.history_mgr = HistoryManager()
        self.sni_scanner = SNIScanner(self.settings)
        self.worker: Optional[ScannerWorkerThread] = None

        self.all_results: List[ScanResult] = []
        self.displayed_results: List[ScanResult] = []
        self.row_to_result_map: Dict[int, ScanResult] = {}
        self.user_wordlist: List[str] = []

        self._init_ui()
        self._setup_shortcuts()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 12, 18, 12)
        main_layout.setSpacing(10)

        # 1. Header Section: Title & Subtitle (Compact)
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)
        title_lbl = QLabel("اسکنر SNI")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #FFFFFF;")
        subtitle_lbl = QLabel("شناسایی، کاوش و تست جامع ساب‌دامین‌ها و کاندیداهای SNI")
        subtitle_lbl.setStyleSheet(f"font-size: 12px; color: {Colors.DARK_TEXT_SECONDARY};")
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(subtitle_lbl)
        main_layout.addLayout(header_layout, stretch=0)

        # 2. Six Statistics Cards Row (Compact)
        stats_layout = QHBoxLayout()
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(10)

        self.card_total = StatCard("globe", "مجموع تست‌شده", "0", accent_color=Colors.NEON_BLUE)
        self.card_success = StatCard("check", "موفق", "0", "0%", accent_color=Colors.SUCCESS_GREEN)
        self.card_failed = StatCard("x", "ناموفق", "0", "0%", accent_color=Colors.FAILED_RED)
        self.card_dns = StatCard("dns", "تفکیک DNS", "0", accent_color=Colors.DNS_PURPLE)
        self.card_tls = StatCard("lock", "موفقیت TLS", "0", accent_color=Colors.TLS_CYAN)
        self.card_lat = StatCard("clock", "میانگین پینگ", "0 ms", accent_color=Colors.WARNING_AMBER)

        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_success)
        stats_layout.addWidget(self.card_failed)
        stats_layout.addWidget(self.card_dns)
        stats_layout.addWidget(self.card_tls)
        stats_layout.addWidget(self.card_lat)
        main_layout.addLayout(stats_layout, stretch=0)

        # 3. Main Body Splitter: Left area (Table + Details), Right area (Scan Config + Quick Actions + Progress)
        body_splitter = QSplitter(Qt.Horizontal)
        body_splitter.setChildrenCollapsible(False)

        # --- LEFT CONTAINER ---
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        # Toolbar: Search, Status Filter, Sort By, Sort Order
        toolbar_frame = QFrame()
        toolbar_frame.setProperty("class", "CardFrame")
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(10, 6, 10, 6)
        toolbar_layout.setSpacing(10)

        # Search Bar
        search_icon = QLabel()
        search_icon.setPixmap(get_pixmap("search", color=Colors.DARK_TEXT_MUTED, size=16))
        toolbar_layout.addWidget(search_icon)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("جستجوی دامنه، SNI، آی‌پی...")
        self.search_input.textChanged.connect(self._apply_filter_and_sort)
        toolbar_layout.addWidget(self.search_input, stretch=2)

        # Filter ComboBox
        filter_lbl = QLabel("فیلتر:")
        filter_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px; font-weight: 600;")
        toolbar_layout.addWidget(filter_lbl)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "همه",
            "موفق",
            "نیمه‌موفق",
            "ناموفق",
            "DNS تایید شده",
            "TLS تایید شده",
            "HTTPS تایید شده",
        ])
        self.filter_combo.currentTextChanged.connect(self._apply_filter_and_sort)
        toolbar_layout.addWidget(self.filter_combo)

        # Sort ComboBox
        sort_lbl = QLabel("مرتب‌سازی:")
        sort_lbl.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px; font-weight: 600;")
        toolbar_layout.addWidget(sort_lbl)

        self.sort_combo = QComboBox()
        self.sort_combo.addItems([
            "پینگ",
            "نام هاست",
            "آدرس IP",
            "وضعیت",
            "TLS",
            "DNS",
        ])
        self.sort_combo.currentTextChanged.connect(self._apply_filter_and_sort)
        toolbar_layout.addWidget(self.sort_combo)

        self.sort_order_btn = QPushButton("▲ صعودی")
        self.sort_order_btn.setFixedWidth(80)
        self.sort_order_btn.clicked.connect(self._toggle_sort_order)
        toolbar_layout.addWidget(self.sort_order_btn)

        left_layout.addWidget(toolbar_frame)

        # Central Table & Details Splitter (Vertical)
        table_splitter = QSplitter(Qt.Vertical)
        table_splitter.setChildrenCollapsible(False)

        # High-density Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(11)
        self.results_table.setHorizontalHeaderLabels([
            "✓",
            "دامنه / SNI",
            "آدرس IP",
            "DNS",
            "TCP",
            "TLS",
            "HTTPS",
            "وضعیت",
            "پینگ",
            "گواهی",
            "عملیات",
        ])

        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        self.results_table.setColumnWidth(0, 36)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        self.results_table.setColumnWidth(2, 130)
        header.setSectionResizeMode(3, QHeaderView.Fixed)
        self.results_table.setColumnWidth(3, 50)
        header.setSectionResizeMode(4, QHeaderView.Fixed)
        self.results_table.setColumnWidth(4, 50)
        header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.results_table.setColumnWidth(5, 50)
        header.setSectionResizeMode(6, QHeaderView.Fixed)
        self.results_table.setColumnWidth(6, 60)
        header.setSectionResizeMode(7, QHeaderView.Interactive)
        self.results_table.setColumnWidth(7, 90)
        header.setSectionResizeMode(8, QHeaderView.Interactive)
        self.results_table.setColumnWidth(8, 90)
        header.setSectionResizeMode(9, QHeaderView.Stretch)
        header.setSectionResizeMode(10, QHeaderView.Fixed)
        self.results_table.setColumnWidth(10, 92)

        self.results_table.verticalHeader().setVisible(False)
        self.results_table.verticalHeader().setDefaultSectionSize(40)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._show_context_menu)
        self.results_table.itemSelectionChanged.connect(self._on_table_row_selected)
        self.results_table.itemDoubleClicked.connect(self._on_table_double_clicked)

        table_splitter.addWidget(self.results_table)

        # 4. Result Details Panel (Below Table)
        self.details_panel = self._create_details_panel()
        table_splitter.addWidget(self.details_panel)
        table_splitter.setSizes([380, 200])

        left_layout.addWidget(table_splitter)
        body_splitter.addWidget(left_container)

        # --- RIGHT CONTAINER: CONFIG, QUICK ACTIONS, PROGRESS ---
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_scroll.setFixedWidth(320)
        right_scroll.setFrameShape(QFrame.NoFrame)
        right_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        right_scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 8, 0)
        right_layout.setSpacing(10)

        # 5. Scan Configuration Panel
        config_frame = QFrame()
        config_frame.setObjectName("ConfigCard")
        config_frame.setProperty("class", "CardFrame")
        config_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        c_layout = QVBoxLayout(config_frame)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        c_title = QLabel("پیکربندی اسکن")
        c_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        c_layout.addWidget(c_title)

        # Domain Input & Random Domain Action
        c_layout.addWidget(QLabel("دامنه هدف (خالی = انتخاب تصادفی):"))
        domain_row = QHBoxLayout()
        domain_row.setSpacing(6)

        self.domain_input = QLineEdit()
        self.domain_input.setFixedHeight(34)
        self.domain_input.setPlaceholderText("مثال: cloudflare.com یا خالی...")
        self.domain_input.setText("")
        domain_row.addWidget(self.domain_input, stretch=1)

        self.rand_domain_btn = QPushButton("🎲 تصادفی")
        self.rand_domain_btn.setFixedHeight(34)
        self.rand_domain_btn.setToolTip("انتخاب یک دامنه تصادفی معتبر از لیست")
        self.rand_domain_btn.clicked.connect(self._pick_random_domain)
        domain_row.addWidget(self.rand_domain_btn)

        c_layout.addLayout(domain_row)

        # Result Count Presets
        c_layout.addWidget(QLabel("تعداد تارگت:"))
        preset_layout = QHBoxLayout()
        preset_layout.setSpacing(4)
        self.preset_combo = QComboBox()
        self.preset_combo.setFixedHeight(34)
        self.preset_combo.addItems(["10", "50", "100", "500", "دلخواه"])
        self.preset_combo.setCurrentText("50")
        self.preset_combo.currentTextChanged.connect(self._on_preset_changed)
        preset_layout.addWidget(self.preset_combo, stretch=1)

        self.custom_count_spin = QSpinBox()
        self.custom_count_spin.setFixedHeight(34)
        self.custom_count_spin.setRange(1, 10000)
        self.custom_count_spin.setValue(100)
        self.custom_count_spin.setVisible(False)
        preset_layout.addWidget(self.custom_count_spin, stretch=1)
        c_layout.addLayout(preset_layout)

        # Dataset / Source
        c_layout.addWidget(QLabel("منبع کاندیداها:"))
        self.source_combo = QComboBox()
        self.source_combo.setFixedHeight(34)
        self.source_combo.addItems([
            "لیست عمومی DNS و ساب‌دامین‌ها",
            "لاگ‌های گواهی عمومی (crt.sh)",
            "وردلیست دلخواه کاربر",
            "فایل متنی / CSV وارد شده",
            "ترکیب همه منابع",
        ])
        self.source_combo.currentTextChanged.connect(self._on_source_changed)
        c_layout.addWidget(self.source_combo)

        self.wordlist_btn = QPushButton("انتخاب وردلیست...")
        self.wordlist_btn.setFixedHeight(32)
        self.wordlist_btn.setIcon(get_icon("search", color=Colors.NEON_BLUE, size=16))
        self.wordlist_btn.clicked.connect(self._load_user_wordlist)
        self.wordlist_btn.setVisible(False)
        c_layout.addWidget(self.wordlist_btn)

        self.wordlist_lbl = QLabel("")
        self.wordlist_lbl.setStyleSheet(f"font-size: 11px; color: {Colors.NEON_BLUE};")
        self.wordlist_lbl.setVisible(False)
        c_layout.addWidget(self.wordlist_lbl)

        # Start Scan Action Buttons
        self.start_btn = QPushButton("شروع اسکن")
        self.start_btn.setObjectName("StartScanBtn")
        self.start_btn.setProperty("class", "PrimaryBtn")
        self.start_btn.setFixedHeight(38)
        self.start_btn.setIcon(get_icon("play", color="#FFFFFF", size=18))
        self.start_btn.clicked.connect(self.start_scan)
        c_layout.addWidget(self.start_btn)

        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(6)

        self.stop_btn = QPushButton("توقف")
        self.stop_btn.setObjectName("StopScanBtn")
        self.stop_btn.setProperty("class", "DangerBtn")
        self.stop_btn.setFixedHeight(32)
        self.stop_btn.setIcon(get_icon("stop", color="#FFFFFF", size=14))
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.stop_btn)

        self.pause_btn = QPushButton("مکث")
        self.pause_btn.setProperty("class", "WarningBtn")
        self.pause_btn.setFixedHeight(32)
        self.pause_btn.setIcon(get_icon("pause", color="#FFFFFF", size=14))
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        controls_layout.addWidget(self.pause_btn)

        self.retry_btn = QPushButton("تکرار ناموفق‌ها")
        self.retry_btn.setFixedHeight(32)
        self.retry_btn.setIcon(get_icon("refresh", color=Colors.NEON_BLUE, size=14))
        self.retry_btn.clicked.connect(self.retry_failed)
        controls_layout.addWidget(self.retry_btn)

        c_layout.addLayout(controls_layout)
        right_layout.addWidget(config_frame)

        # 6. Quick Actions Card
        qa_frame = QFrame()
        qa_frame.setProperty("class", "CardFrame")
        qa_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        qa_layout = QVBoxLayout(qa_frame)
        qa_layout.setContentsMargins(14, 12, 14, 12)
        qa_layout.setSpacing(8)

        qa_title = QLabel("عملیات سریع")
        qa_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #FFFFFF;")
        qa_layout.addWidget(qa_title)

        qa_btn_grid = QVBoxLayout()
        qa_btn_grid.setSpacing(6)

        copy_sel_btn = QPushButton("کپی انتخاب‌شده‌ها")
        copy_sel_btn.setFixedHeight(32)
        copy_sel_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=14))
        copy_sel_btn.clicked.connect(self.copy_selected)
        qa_btn_grid.addWidget(copy_sel_btn)

        copy_all_btn = QPushButton("کپی همه نتایج")
        copy_all_btn.setFixedHeight(32)
        copy_all_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=14))
        copy_all_btn.clicked.connect(self.copy_all)
        qa_btn_grid.addWidget(copy_all_btn)

        clear_btn = QPushButton("پاکسازی نتایج")
        clear_btn.setFixedHeight(32)
        clear_btn.setIcon(get_icon("trash", color=Colors.FAILED_RED, size=14))
        clear_btn.clicked.connect(self.clear_results)
        qa_btn_grid.addWidget(clear_btn)

        qa_layout.addLayout(qa_btn_grid)

        # Export Buttons
        export_title = QLabel("خروجی نتایج")
        export_title.setStyleSheet("font-size: 12px; font-weight: 600; color: #FFFFFF; margin-top: 4px;")
        qa_layout.addWidget(export_title)

        exp_layout = QHBoxLayout()
        exp_layout.setSpacing(4)

        btn_txt = QPushButton("TXT")
        btn_txt.setFixedHeight(30)
        btn_txt.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_txt.clicked.connect(lambda: self.export_results("txt"))
        exp_layout.addWidget(btn_txt)

        btn_csv = QPushButton("CSV")
        btn_csv.setFixedHeight(30)
        btn_csv.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_csv.clicked.connect(lambda: self.export_results("csv"))
        exp_layout.addWidget(btn_csv)

        btn_json = QPushButton("JSON")
        btn_json.setFixedHeight(30)
        btn_json.setIcon(get_icon("download", color=Colors.NEON_BLUE, size=12))
        btn_json.clicked.connect(lambda: self.export_results("json"))
        exp_layout.addWidget(btn_json)

        qa_layout.addLayout(exp_layout)
        right_layout.addWidget(qa_frame)

        # 7. Progress Panel Card
        progress_frame = QFrame()
        progress_frame.setObjectName("ProgressCard")
        progress_frame.setProperty("class", "CardFrame")
        progress_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        p_layout = QVBoxLayout(progress_frame)
        p_layout.setContentsMargins(14, 12, 14, 12)
        p_layout.setSpacing(6)

        p_header = QHBoxLayout()
        self.p_title = QLabel("پیشرفت اسکن")
        self.p_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #FFFFFF;")
        p_header.addWidget(self.p_title)
        p_header.addStretch()

        self.p_pct_lbl = QLabel("۰%")
        self.p_pct_lbl.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {Colors.NEON_BLUE};")
        p_header.addWidget(self.p_pct_lbl)
        p_layout.addLayout(p_header)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        p_layout.addWidget(self.progress_bar)

        self.p_detail_lbl = QLabel("۰ / ۰ تست‌شده")
        self.p_detail_lbl.setStyleSheet(f"font-size: 11px; color: {Colors.DARK_TEXT_SECONDARY};")
        p_layout.addWidget(self.p_detail_lbl)

        self.p_op_lbl = QLabel("آماده")
        self.p_op_lbl.setStyleSheet(f"font-size: 10px; color: {Colors.DARK_TEXT_MUTED};")
        p_layout.addWidget(self.p_op_lbl)

        right_layout.addWidget(progress_frame)
        right_layout.addStretch()

        right_scroll.setWidget(right_container)
        body_splitter.addWidget(right_scroll)
        body_splitter.setSizes([900, 320])

        main_layout.addWidget(body_splitter, stretch=1)

    def _create_details_panel(self) -> QFrame:
        """Create the lower multi-tab inspection panel."""
        panel = QFrame()
        panel.setObjectName("DetailsCard")
        panel.setProperty("class", "CardFrame")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        # Tab widget for Connection, DNS, TLS, and HTTP
        self.details_tabs = QTabWidget()

        # Tab 1: Connection
        conn_widget = QWidget()
        conn_layout = QHBoxLayout(conn_widget)
        self.conn_text = QLabel("یک سطر را در جدول بالا انتخاب کنید تا جزئیات اتصال نمایش داده شود.")
        self.conn_text.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        self.conn_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        conn_layout.addWidget(self.conn_text)
        self.details_tabs.addTab(conn_widget, "اتصال و شبکه")

        # Tab 2: DNS
        dns_widget = QWidget()
        dns_layout = QHBoxLayout(dns_widget)
        self.dns_text = QLabel("اطلاعات رکوردهای DNS در دسترس نیست.")
        self.dns_text.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        self.dns_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        dns_layout.addWidget(self.dns_text)
        self.details_tabs.addTab(dns_widget, "رکوردهای DNS")

        # Tab 3: TLS
        tls_widget = QWidget()
        tls_layout = QHBoxLayout(tls_widget)
        self.tls_text = QLabel("اطلاعات گواهی و TLS در دسترس نیست.")
        self.tls_text.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        self.tls_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        tls_layout.addWidget(self.tls_text)
        self.details_tabs.addTab(tls_widget, "گواهی و TLS")

        # Tab 4: HTTP
        http_widget = QWidget()
        http_layout = QHBoxLayout(http_widget)
        self.http_text = QLabel("اطلاعات کاوش HTTP در دسترس نیست.")
        self.http_text.setStyleSheet(f"color: {Colors.DARK_TEXT_SECONDARY}; font-size: 11px;")
        self.http_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        http_layout.addWidget(self.http_text)
        self.details_tabs.addTab(http_widget, "کاوش HTTP")

        layout.addWidget(self.details_tabs)
        return panel

    def _setup_shortcuts(self) -> None:
        """Register keyboard shortcuts."""
        copy_shortcut = QShortcut(QKeySequence("Ctrl+C"), self)
        copy_shortcut.activated.connect(self.copy_selected)

        select_all_shortcut = QShortcut(QKeySequence("Ctrl+A"), self)
        select_all_shortcut.activated.connect(self.results_table.selectAll)

        search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        search_shortcut.activated.connect(lambda: self.search_input.setFocus())

        export_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        export_shortcut.activated.connect(lambda: self.export_results("json"))

        retry_shortcut = QShortcut(QKeySequence("F5"), self)
        retry_shortcut.activated.connect(self.retry_failed)

    def _pick_random_domain(self) -> str:
        """Select a random candidate domain and set it in domain_input."""
        import random
        from pathlib import Path
        candidates = [
            "cloudflare.com", "google.com", "fastly.net", "microsoft.com",
            "amazon.com", "apple.com", "github.com", "wikipedia.org",
            "bing.com", "yahoo.com", "netflix.com", "spotify.com",
            "zoom.us", "reddit.com", "twitch.tv", "discord.com",
            "telegram.org", "akamai.com"
        ]
        try:
            candidates_file = Path(__file__).resolve().parent.parent / "data" / "datasets" / "sni_candidates.txt"
            if candidates_file.exists():
                with open(candidates_file, "r", encoding="utf-8") as f:
                    file_domains = [line.strip() for line in f if line.strip() and not line.startswith("#") and "." in line]
                    apex_candidates = [d for d in file_domains if d.count(".") <= 2 and not d.startswith("*")]
                    if apex_candidates:
                        candidates = apex_candidates
        except Exception:
            pass
        chosen = random.choice(candidates)
        self.domain_input.setText(chosen)
        return chosen

    def _on_preset_changed(self, text: str) -> None:
        self.custom_count_spin.setVisible(text in ("Custom", "دلخواه"))

    def _on_source_changed(self, text: str) -> None:
        is_user = "وردلیست" in text or "User" in text or "CSV" in text or "وارد شده" in text
        self.wordlist_btn.setVisible(is_user)
        self.wordlist_lbl.setVisible(is_user)

    def _load_user_wordlist(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self, "انتخاب وردلیست ساب‌دامین", "", "فایل متنی (*.txt *.csv);;همه فایل‌ها (*.*)"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.user_wordlist = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
                self.wordlist_lbl.setText(f"{len(self.user_wordlist)} آیتم بارگذاری شد")
            except Exception:
                pass

    def _get_target_count(self) -> int:
        preset = self.preset_combo.currentText()
        if preset in ("Custom", "دلخواه"):
            return self.custom_count_spin.value()
        try:
            return int(preset)
        except ValueError:
            return 50

    def start_scan(self) -> None:
        """Initiate background multi-stage scanning."""
        domain = self.domain_input.text().strip()
        # Fallback to random domain if empty or invalid
        if not domain:
            domain = self._pick_random_domain()

        if not is_valid_domain(domain):
            domain = self._pick_random_domain()

        count = self._get_target_count()
        source_text = self.source_combo.currentText()
        if "crt.sh" in source_text:
            source = "crtsh"
        elif "وردلیست" in source_text or "User" in source_text or "CSV" in source_text or "وارد شده" in source_text:
            source = "user"
        elif "ترکیب" in source_text or "Combined" in source_text:
            source = "all"
        else:
            source = "builtin"

        self.clear_results(confirm=False)

        # Candidate discovery
        self.p_op_lbl.setText("در حال استخراج کاندیداها...")
        targets = self.sni_scanner.discover_candidates(
            domain=domain,
            limit=count,
            source=source,
            user_wordlist=self.user_wordlist if self.user_wordlist else None,
        )

        if not targets:
            self.p_op_lbl.setText("هیچ کاندیدایی یافت نشد")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setEnabled(True)
        self.pause_btn.setText("مکث")

        self.p_pct_lbl.setText("۰%")
        self.p_detail_lbl.setText(f"۰ / {len(targets)} تست‌شده")
        self.progress_bar.setValue(0)

        self.worker = ScannerWorkerThread(self.sni_scanner, targets, self)
        self.worker.progress_signal.connect(self._on_scan_progress)
        self.worker.result_signal.connect(self._on_result_received)
        self.worker.finished_signal.connect(self._on_scan_finished)
        self.worker.start()

        self.status_updated.emit("running", "در حال اسکن ساب‌دامین‌ها...", 0, len(targets), 0, 0.0)

    def stop_scan(self) -> None:
        """Cancel ongoing scan."""
        if self.sni_scanner:
            self.sni_scanner.cancel()
        if self.worker and self.worker.isRunning():
            self.worker.wait(1000)

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.p_op_lbl.setText("Scan cancelled")
        ToastNotification("Scan cancelled", self)
        self.status_updated.emit("ready", "Ready", 0, 0, 0, 0.0)

    def toggle_pause(self) -> None:
        """Pause or resume running scan."""
        if not self.sni_scanner:
            return
        if self.sni_scanner.is_paused:
            self.sni_scanner.resume()
            self.pause_btn.setText("Pause")
            self.pause_btn.setIcon(get_icon("pause", color="#FFFFFF", size=14))
            self.p_op_lbl.setText("Scan resumed")
            ToastNotification("Scan resumed", self)
        else:
            self.sni_scanner.pause()
            self.pause_btn.setText("Resume")
            self.pause_btn.setIcon(get_icon("play", color="#FFFFFF", size=14))
            self.p_op_lbl.setText("Scan paused")
            ToastNotification("Scan paused", self)

    def retry_failed(self) -> None:
        """Filter failed targets and retry diagnostic scan."""
        failed_targets = [r.target for r in self.all_results if r.status == ScanStatus.FAILED]
        if not failed_targets:
            ToastNotification("No failed targets to retry", self)
            return

        # Remove failed items from table & list
        self.all_results = [r for r in self.all_results if r.status != ScanStatus.FAILED]
        self._apply_filter_and_sort()
        self._update_stats()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.pause_btn.setEnabled(True)

        self.worker = ScannerWorkerThread(self.sni_scanner, failed_targets, self)
        self.worker.progress_signal.connect(self._on_scan_progress)
        self.worker.result_signal.connect(self._on_result_received)
        self.worker.finished_signal.connect(self._on_scan_finished)
        self.worker.start()

        ToastNotification(f"Retrying {len(failed_targets)} failed targets", self)

    def _on_scan_progress(self, tested: int, total: int, current_op: str) -> None:
        pct = int((tested / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.p_pct_lbl.setText(f"{pct}%")
        self.p_detail_lbl.setText(f"{tested} / {total} تست‌شده")
        self.p_op_lbl.setText(current_op)

        # Emit to bottom status bar
        success = sum(1 for r in self.all_results if r.status == ScanStatus.SUCCESS)
        failed = sum(1 for r in self.all_results if r.status == ScanStatus.FAILED)
        avg_lat = (sum(r.total_latency_ms for r in self.all_results if r.total_latency_ms > 0) / len(self.all_results)) if self.all_results else 0.0
        self.status_updated.emit("running", current_op, tested, total, success, avg_lat)

    def _on_result_received(self, res: ScanResult) -> None:
        self.all_results.append(res)
        self._update_stats()
        self._apply_filter_and_sort()

    def _on_scan_finished(self, session: ScanSession, results: List[ScanResult]) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setEnabled(False)
        self.p_op_lbl.setText("اسکن کامل شد")

        # Save to SQLite history
        self.history_mgr.save_session(session, results)

        self.status_updated.emit("ready", "اسکن کامل شد", len(results), len(results), session.successful_count, session.avg_latency_ms)

    def _update_stats(self) -> None:
        """Recalculate dynamic statistics cards based on real scan outcomes."""
        total = len(self.all_results)
        success = sum(1 for r in self.all_results if r.status == ScanStatus.SUCCESS)
        failed = sum(1 for r in self.all_results if r.status == ScanStatus.FAILED)
        dns_res = sum(1 for r in self.all_results if r.dns.resolved)
        tls_succ = sum(1 for r in self.all_results if r.tls.handshake_success)

        lat_samples = [r.total_latency_ms for r in self.all_results if r.total_latency_ms > 0]
        avg_lat = (sum(lat_samples) / len(lat_samples)) if lat_samples else 0.0

        succ_pct = f"{int((success / total) * 100)}%" if total > 0 else "0%"
        fail_pct = f"{int((failed / total) * 100)}%" if total > 0 else "0%"

        self.card_total.set_value(str(total))
        self.card_success.set_value(str(success), succ_pct)
        self.card_failed.set_value(str(failed), fail_pct)
        self.card_dns.set_value(str(dns_res))
        self.card_tls.set_value(str(tls_succ))
        self.card_lat.set_value(f"{avg_lat:.0f} ms")

    def _apply_filter_and_sort(self) -> None:
        """Filter and sort results table dynamically."""
        query = self.search_input.text().strip().lower()
        filter_type = self.filter_combo.currentText()
        sort_by = self.sort_combo.currentText()
        is_asc = "صعودی" in self.sort_order_btn.text() or "Asc" in self.sort_order_btn.text()

        # 1. Filter
        filtered = []
        for r in self.all_results:
            # Search query match
            if query:
                match_host = query in r.target.hostname.lower()
                match_sni = query in (r.target.sni or "").lower()
                match_ip = query in r.display_ip.lower()
                match_cert = query in (r.tls.certificate.subject or "").lower()
                if not (match_host or match_sni or match_ip or match_cert):
                    continue

            # Status filter
            if filter_type in ("Success", "موفق") and r.status != ScanStatus.SUCCESS:
                continue
            if filter_type in ("Partial", "نیمه‌موفق") and r.status != ScanStatus.PARTIAL:
                continue
            if filter_type in ("Failed", "ناموفق") and r.status != ScanStatus.FAILED:
                continue
            if (filter_type in ("DNS Resolved", "DNS تایید شده") or "DNS" in filter_type) and not r.dns.resolved:
                continue
            if (filter_type in ("TLS Successful", "TLS تایید شده") or "TLS" in filter_type) and not r.tls.handshake_success:
                continue
            if (filter_type in ("HTTPS Successful", "HTTPS تایید شده") or "HTTPS" in filter_type) and not (r.http.reachable or r.http.status_code > 0):
                continue

            filtered.append(r)

        # 2. Sort
        if sort_by in ("Latency", "پینگ"):
            filtered.sort(key=lambda x: x.total_latency_ms, reverse=not is_asc)
        elif sort_by in ("Hostname", "نام هاست"):
            filtered.sort(key=lambda x: x.target.hostname.lower(), reverse=not is_asc)
        elif sort_by in ("IP", "آدرس IP"):
            filtered.sort(key=lambda x: x.display_ip, reverse=not is_asc)
        elif sort_by in ("Status", "وضعیت"):
            filtered.sort(key=lambda x: x.status.value, reverse=not is_asc)
        elif "TLS" in sort_by:
            filtered.sort(key=lambda x: (x.tls.handshake_success, x.tls.tls_version), reverse=not is_asc)
        elif "DNS" in sort_by:
            filtered.sort(key=lambda x: (x.dns.resolved, len(x.dns.ipv4_addresses)), reverse=not is_asc)

        self.displayed_results = filtered
        self._populate_table(filtered)

    def _toggle_sort_order(self) -> None:
        if "صعودی" in self.sort_order_btn.text() or "Asc" in self.sort_order_btn.text():
            self.sort_order_btn.setText("▼ نزولی")
        else:
            self.sort_order_btn.setText("▲ صعودی")
        self._apply_filter_and_sort()

    def _populate_table(self, results: List[ScanResult]) -> None:
        """Render rows into high-density QTableWidget with indicators."""
        self.results_table.setRowCount(len(results))
        self.row_to_result_map.clear()

        for row_idx, r in enumerate(results):
            self.row_to_result_map[row_idx] = r

            # Col 0: Checkbox
            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk = QCheckBox()
            chk_layout.addWidget(chk)
            self.results_table.setCellWidget(row_idx, 0, chk_widget)

            # Col 1: SNI / Hostname
            host_item = QTableWidgetItem(r.target.hostname)
            host_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            host_item.setForeground(QColor("#FFFFFF"))
            self.results_table.setItem(row_idx, 1, host_item)

            # Col 2: IP Address
            ip_item = QTableWidgetItem(r.display_ip)
            ip_item.setForeground(QColor(Colors.NEON_BLUE))
            self.results_table.setItem(row_idx, 2, ip_item)

            # Col 3: DNS Indicator
            dns_state = "success" if r.dns.resolved else "failed"
            dns_ind = CircularStatusIndicator(state=dns_state, size=18)
            dns_cell = self._wrap_indicator(dns_ind)
            self.results_table.setCellWidget(row_idx, 3, dns_cell)

            # Col 4: TCP Indicator
            tcp_state = "success" if r.tcp.connected else ("failed" if r.dns.resolved else "none")
            tcp_ind = CircularStatusIndicator(state=tcp_state, size=18)
            tcp_cell = self._wrap_indicator(tcp_ind)
            self.results_table.setCellWidget(row_idx, 4, tcp_cell)

            # Col 5: TLS Indicator
            tls_state = "success" if r.tls.handshake_success else ("failed" if r.tcp.connected else "none")
            tls_ind = CircularStatusIndicator(state=tls_state, size=18)
            tls_cell = self._wrap_indicator(tls_ind)
            self.results_table.setCellWidget(row_idx, 5, tls_cell)

            # Col 6: HTTPS Indicator
            http_state = "success" if (r.http.reachable or r.http.status_code > 0) else ("failed" if r.tls.handshake_success else "none")
            http_ind = CircularStatusIndicator(state=http_state, size=18)
            http_cell = self._wrap_indicator(http_ind)
            self.results_table.setCellWidget(row_idx, 6, http_cell)

            # Col 7: Status Badge
            status_text = "موفق" if r.status == ScanStatus.SUCCESS else ("نیمه‌موفق" if r.status == ScanStatus.PARTIAL else "ناموفق")
            status_item = QTableWidgetItem(status_text)
            if r.status == ScanStatus.SUCCESS:
                status_item.setForeground(QColor(Colors.SUCCESS_GREEN))
            elif r.status == ScanStatus.PARTIAL:
                status_item.setForeground(QColor(Colors.WARNING_AMBER))
            else:
                status_item.setForeground(QColor(Colors.FAILED_RED))
            status_item.setTextAlignment(Qt.AlignCenter)
            self.results_table.setItem(row_idx, 7, status_item)

            # Col 8: Latency
            lat_item = QTableWidgetItem(r.display_latency)
            lat_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.results_table.setItem(row_idx, 8, lat_item)

            # Col 9: Certificate
            cert_summary = r.tls.certificate.subject.replace("commonName=", "") if r.tls.certificate.subject else (r.tls.error or "ندارد")
            cert_item = QTableWidgetItem(cert_summary)
            cert_item.setForeground(QColor(Colors.DARK_TEXT_SECONDARY))
            self.results_table.setItem(row_idx, 9, cert_item)

            # Col 10: Actions (Copy & Inspect)
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 2, 4, 2)
            action_layout.setSpacing(6)
            action_layout.setAlignment(Qt.AlignCenter)

            cp_btn = QPushButton()
            cp_btn.setFixedSize(28, 26)
            cp_btn.setIcon(get_icon("copy", color=Colors.NEON_BLUE, size=13))
            cp_btn.setToolTip("کپی هاست و آی‌پی")
            cp_btn.setCursor(Qt.PointingHandCursor)
            cp_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(0, 212, 255, 0.12);
                    border: 1px solid rgba(0, 212, 255, 0.35);
                    border-radius: 4px;
                    padding: 0px;
                }
                QPushButton:hover {
                    background-color: rgba(0, 212, 255, 0.28);
                    border: 1px solid #00d4ff;
                }
            """)
            cp_btn.clicked.connect(lambda _, host=r.target.hostname, ip=r.display_ip: self._copy_cell(f"{host} ({ip})"))
            action_layout.addWidget(cp_btn)

            view_btn = QPushButton()
            view_btn.setFixedSize(28, 26)
            view_btn.setIcon(get_icon("search", color="#94A3B8", size=13))
            view_btn.setToolTip("مشاهده جزئیات کامل")
            view_btn.setCursor(Qt.PointingHandCursor)
            view_btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(255, 255, 255, 0.08);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    border-radius: 4px;
                    padding: 0px;
                }
                QPushButton:hover {
                    background-color: rgba(255, 255, 255, 0.2);
                    border: 1px solid #ffffff;
                }
            """)
            view_btn.clicked.connect(lambda _, res_ref=r: self._open_details_modal(res_ref))
            action_layout.addWidget(view_btn)

            self.results_table.setCellWidget(row_idx, 10, action_widget)

    def _wrap_indicator(self, indicator: QWidget) -> QWidget:
        container = QWidget()
        lay = QHBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setAlignment(Qt.AlignCenter)
        lay.addWidget(indicator)
        return container

    def _on_table_row_selected(self) -> None:
        """Update bottom details panel dynamically when selected row changes."""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row_idx = selected_rows[0].row()
        result = self.row_to_result_map.get(row_idx)
        if not result:
            return

        # 1. Update Connection Tab
        conn_html = f"""
        <table style="width: 100%; border-collapse: collapse; font-family: Segoe UI, Tahoma, sans-serif;">
            <tr><td style="color: #94A3B8; width: 140px;"><b>دامنه / هاست:</b></td><td style="color: #FFFFFF;"><b>{result.target.hostname}</b></td></tr>
            <tr><td style="color: #94A3B8;"><b>آدرس IP:</b></td><td style="color: {Colors.NEON_BLUE};">{result.display_ip}</td></tr>
            <tr><td style="color: #94A3B8;"><b>پورت / پروتکل:</b></td><td style="color: #E2E8F0;">{result.target.port} / {result.target.protocol.upper()}</td></tr>
            <tr><td style="color: #94A3B8;"><b>وضعیت TCP:</b></td><td style="color: {'#34D399' if result.tcp.connected else '#F87171'};">{'متصل شد' if result.tcp.connected else 'خطای اتصال'} (پینگ: {result.tcp.latency_ms:.1f}ms)</td></tr>
            <tr><td style="color: #94A3B8;"><b>وضعیت نهایی:</b></td><td style="color: #F8FAFC;"><b>{'موفق' if result.status == ScanStatus.SUCCESS else ('نیمه‌موفق' if result.status == ScanStatus.PARTIAL else 'ناموفق')}</b> (تاخیر کل: {result.display_latency})</td></tr>
        </table>
        """
        self.conn_text.setText(conn_html)

        # 2. Update DNS Tab
        dns_html = f"""
        <table style="width: 100%; border-collapse: collapse; font-family: Segoe UI, Tahoma, sans-serif;">
            <tr><td style="color: #94A3B8; width: 140px;"><b>وضعیت DNS:</b></td><td style="color: {'#34D399' if result.dns.resolved else '#F87171'};"><b>{'تفکیک موفق' if result.dns.resolved else 'ناموفق'}</b> (پینگ: {result.dns.latency_ms:.1f}ms)</td></tr>
            <tr><td style="color: #94A3B8;"><b>آدرس‌های IPv4:</b></td><td style="color: {Colors.NEON_BLUE};">{', '.join(result.dns.ipv4_addresses) or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>آدرس‌های IPv6:</b></td><td style="color: {Colors.DNS_PURPLE};">{', '.join(result.dns.ipv6_addresses) or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>رکوردهای CNAME:</b></td><td style="color: #E2E8F0;">{', '.join(result.dns.cnames) or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>سرورهای نام (NS):</b></td><td style="color: #94A3B8;">{', '.join(result.dns.nameservers) or 'پیش‌فرض سیستم'}</td></tr>
        </table>
        """
        self.dns_text.setText(dns_html)

        # 3. Update TLS Tab
        cert = result.tls.certificate
        tls_html = f"""
        <table style="width: 100%; border-collapse: collapse; font-family: Segoe UI, Tahoma, sans-serif;">
            <tr><td style="color: #94A3B8; width: 140px;"><b>هندشیک TLS:</b></td><td style="color: {'#34D399' if result.tls.handshake_success else '#F87171'};"><b>{'موفق' if result.tls.handshake_success else 'ناموفق'}</b> ({result.tls.tls_version} {result.tls.cipher})</td></tr>
            <tr><td style="color: #94A3B8;"><b>هدر SNI ارسالی:</b></td><td style="color: #FFFFFF;"><b>{result.tls.sni_used}</b> (تطابق با گواهی: {'بله' if result.tls.certificate_matches_sni else 'خیر'})</td></tr>
            <tr><td style="color: #94A3B8;"><b>موضوع (Subject):</b></td><td style="color: #E2E8F0;">{cert.subject or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>صادرکننده (Issuer):</b></td><td style="color: #E2E8F0;">{cert.issuer or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>اعتبار زمانی:</b></td><td style="color: {'#34D399' if cert.is_valid else '#F59E0B'};">{cert.valid_from} تا {cert.valid_until} {'(منقضی شده)' if cert.is_expired else ''}</td></tr>
            <tr><td style="color: #94A3B8;"><b>نام‌های جایگزین (SAN):</b></td><td style="color: {Colors.NEON_BLUE};">{', '.join(cert.subject_alt_names[:10]) + ('...' if len(cert.subject_alt_names) > 10 else '') or 'ندارد'}</td></tr>
        </table>
        """
        self.tls_text.setText(tls_html)

        # 4. Update HTTP Tab
        http = result.http
        http_html = f"""
        <table style="width: 100%; border-collapse: collapse; font-family: Segoe UI, Tahoma, sans-serif;">
            <tr><td style="color: #94A3B8; width: 140px;"><b>دسترسی HTTP:</b></td><td style="color: {'#34D399' if http.reachable else '#F87171'};"><b>{'بله' if http.reachable else 'خیر'}</b> (تاخیر: {http.latency_ms:.1f}ms)</td></tr>
            <tr><td style="color: #94A3B8;"><b>کد وضعیت:</b></td><td style="color: {Colors.NEON_BLUE};"><b>{http.status_code if http.status_code > 0 else 'نامشخص'}</b></td></tr>
            <tr><td style="color: #94A3B8;"><b>هدر سرور:</b></td><td style="color: #E2E8F0;">{http.server_header or 'مخفی / ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>نوع محتوا:</b></td><td style="color: #E2E8F0;">{http.content_type or 'ندارد'}</td></tr>
            <tr><td style="color: #94A3B8;"><b>آدرس ریدایرکت:</b></td><td style="color: #FBBF24;">{http.redirect_url or 'ندارد'}</td></tr>
        </table>
        """
        self.http_text.setText(http_html)

    def _on_table_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        result = self.row_to_result_map.get(row)
        if result:
            self._open_details_modal(result)

    def _open_details_modal(self, result: ScanResult) -> None:
        dlg = ResultDetailsDialog(result, self)
        dlg.exec()

    def _copy_cell(self, text: str) -> None:
        copy_text_to_clipboard(text)

    def copy_selected(self) -> None:
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        lines = []
        for r_item in selected_rows:
            res = self.row_to_result_map.get(r_item.row())
            if res:
                lines.append(f"{res.target.hostname}\t{res.display_ip}\t{res.status.label}\t{res.display_latency}")

        copy_text_to_clipboard("\n".join(lines))

    def copy_all(self) -> None:
        if not self.all_results:
            return
        lines = [f"{r.target.hostname}\t{r.display_ip}\t{r.status.label}\t{r.display_latency}" for r in self.all_results]
        copy_text_to_clipboard("\n".join(lines))

    def clear_results(self, confirm: bool = True) -> None:
        if confirm and self.all_results:
            dlg = ConfirmDialog(
                title="پاکسازی نتایج اسکن",
                message="آیا مطمئن هستید که می‌خواهید تمام نتایج اسکن فعلی پاک شوند؟",
                confirm_label="پاکسازی نتایج",
                is_danger=True,
                parent=self,
            )
            if dlg.exec() != ConfirmDialog.Accepted:
                return

        self.all_results.clear()
        self.displayed_results.clear()
        self.results_table.setRowCount(0)
        self.row_to_result_map.clear()
        self._update_stats()
        self.conn_text.setText("یک سطر را در جدول بالا انتخاب کنید تا جزئیات اتصال نمایش داده شود.")
        self.dns_text.setText("اطلاعات رکوردهای DNS در دسترس نیست.")
        self.tls_text.setText("اطلاعات گواهی و TLS در دسترس نیست.")
        self.http_text.setText("اطلاعات کاوش HTTP در دسترس نیست.")
        self.progress_bar.setValue(0)
        self.p_pct_lbl.setText("۰%")
        self.p_detail_lbl.setText("۰ / ۰ تست‌شده")
        self.p_op_lbl.setText("آماده")

    def export_results(self, fmt: str) -> None:
        if not self.all_results:
            return

        fmt = fmt.lower()
        ext = f"*.{fmt}"
        filter_str = f"فایل‌های {fmt.upper()} ({ext});;همه فایل‌ها (*.*)"
        file_path, _ = QFileDialog.getSaveFileName(self, f"خروجی نتایج به فرمت {fmt.upper()}", f"nikator_scanner_results.{fmt}", filter_str)
        if not file_path:
            return

        if fmt == "json":
            export_to_json(self.all_results, file_path)
        elif fmt == "csv":
            export_to_csv(self.all_results, file_path)
        elif fmt == "txt":
            export_to_txt(self.all_results, file_path)

    def _show_context_menu(self, pos: QPoint) -> None:
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row_idx = selected_rows[0].row()
        result = self.row_to_result_map.get(row_idx)
        if not result:
            return

        menu = QMenu(self)

        copy_sni_action = menu.addAction(f"کپی هدر SNI: {result.target.sni}")
        copy_host_action = menu.addAction(f"کپی نام دامنه: {result.target.hostname}")
        copy_ip_action = menu.addAction(f"کپی آدرس IP: {result.display_ip}")
        copy_port_action = menu.addAction(f"کپی پورت: {result.target.port}")
        menu.addSeparator()

        copy_row_action = menu.addAction("کپی مشخصات کامل این سطر")
        view_details_action = menu.addAction("مشاهده جزئیات کامل عیب‌یابی...")
        menu.addSeparator()

        export_sel_action = menu.addAction("خروجی موارد انتخاب‌شده به CSV...")

        action = menu.exec(self.results_table.viewport().mapToGlobal(pos))
        if action == copy_sni_action:
            self._copy_cell(result.target.sni or result.target.hostname)
        elif action == copy_host_action:
            self._copy_cell(result.target.hostname)
        elif action == copy_ip_action:
            self._copy_cell(result.display_ip)
        elif action == copy_port_action:
            self._copy_cell(str(result.target.port))
        elif action == copy_row_action:
            self._copy_cell(f"{result.target.hostname}\t{result.display_ip}\t{result.status.label}\t{result.display_latency}")
        elif action == view_details_action:
            self._open_details_modal(result)
        elif action == export_sel_action:
            sel_results = [self.row_to_result_map[r.row()] for r in selected_rows if r.row() in self.row_to_result_map]
            file_path, _ = QFileDialog.getSaveFileName(self, "خروجی موارد انتخاب‌شده به CSV", "selected_results.csv", "CSV Files (*.csv)")
            if file_path:
                export_to_csv(sel_results, file_path)
