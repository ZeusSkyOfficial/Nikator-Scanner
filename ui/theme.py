"""Theme definitions and stylesheet generation for Nikator Scanner.
Provides dark futuristic navy palette, neon accents, status indicators, and SVG icons.
"""

from __future__ import annotations

from typing import Dict


class Colors:
    """Color palette definitions."""
    # Dark Futuristic Theme
    DARK_BG = "#0A0F1D"            # Main application window background
    DARK_SURFACE = "#0F172A"       # Cards and container background
    DARK_SURFACE_ALT = "#162036"   # Secondary elevated cards
    DARK_SURFACE_HOVER = "#1E2D4A" # Card and row hover state
    DARK_BORDER = "#1E293B"        # Subtle card border
    DARK_BORDER_LIGHT = "#334155"  # Active/highlighted border
    DARK_TEXT_PRIMARY = "#F8FAFC"  # High contrast text
    DARK_TEXT_SECONDARY = "#94A3B8"# Muted subtitle text
    DARK_TEXT_MUTED = "#64748B"    # Dim placeholder text

    # Light Theme
    LIGHT_BG = "#F1F5F9"
    LIGHT_SURFACE = "#FFFFFF"
    LIGHT_SURFACE_ALT = "#F8FAFC"
    LIGHT_SURFACE_HOVER = "#E2E8F0"
    LIGHT_BORDER = "#CBD5E1"
    LIGHT_BORDER_LIGHT = "#94A3B8"
    LIGHT_TEXT_PRIMARY = "#0F172A"
    LIGHT_TEXT_SECONDARY = "#475569"
    LIGHT_TEXT_MUTED = "#94A3B8"

    # Accents & Semantics
    NEON_BLUE = "#38BDF8"          # Blue neon highlight
    PRIMARY_BLUE = "#2563EB"       # Primary action blue
    PRIMARY_BLUE_HOVER = "#1D4ED8" # Primary hover
    SUCCESS_GREEN = "#10B981"      # Successful state
    SUCCESS_GREEN_BG = "#064E3B"
    FAILED_RED = "#EF4444"         # Failed state
    FAILED_RED_BG = "#7F1D1D"
    WARNING_AMBER = "#F59E0B"      # Partial / Warning state
    WARNING_AMBER_BG = "#78350F"
    DNS_PURPLE = "#8B5CF6"         # DNS indicators
    DNS_PURPLE_BG = "#4C1D95"
    TLS_CYAN = "#06B6D4"           # TLS indicators
    TLS_CYAN_BG = "#164E63"


def get_theme_stylesheet(is_dark: bool = True, font_size: int = 12) -> str:
    """Generate dynamic Qt style sheet based on current theme and font size."""
    bg = Colors.DARK_BG if is_dark else Colors.LIGHT_BG
    surface = Colors.DARK_SURFACE if is_dark else Colors.LIGHT_SURFACE
    surface_alt = Colors.DARK_SURFACE_ALT if is_dark else Colors.LIGHT_SURFACE_ALT
    surface_hover = Colors.DARK_SURFACE_HOVER if is_dark else Colors.LIGHT_SURFACE_HOVER
    border = Colors.DARK_BORDER if is_dark else Colors.LIGHT_BORDER
    border_light = Colors.DARK_BORDER_LIGHT if is_dark else Colors.LIGHT_BORDER_LIGHT
    text_primary = Colors.DARK_TEXT_PRIMARY if is_dark else Colors.LIGHT_TEXT_PRIMARY
    text_sec = Colors.DARK_TEXT_SECONDARY if is_dark else Colors.LIGHT_TEXT_SECONDARY
    text_muted = Colors.DARK_TEXT_MUTED if is_dark else Colors.LIGHT_TEXT_MUTED

    return f"""
    * {{
        font-size: {font_size}px;
        color: {text_primary};
        outline: none;
    }}

    QMainWindow, QDialog {{
        background-color: {bg};
    }}

    QWidget#CentralWidget, QWidget#MainContentArea {{
        background-color: {bg};
    }}

    /* Card Panels & Containers */
    QFrame.CardFrame, QFrame#StatCard, QFrame#ConfigCard, QFrame#ProgressCard, QFrame#DetailsCard {{
        background-color: {surface};
        border: 1px solid {border};
        border-radius: 10px;
    }}

    QFrame.GlassFrame {{
        background-color: {surface_alt};
        border: 1px solid {border_light};
        border-radius: 8px;
    }}

    /* Left Sidebar */
    QFrame#SidebarFrame {{
        background-color: {surface};
        border-right: 1px solid {border};
    }}

    QPushButton#SidebarNavBtn {{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
        text-align: left;
        padding: 10px 14px;
        font-weight: 500;
        color: {text_sec};
    }}

    QPushButton#SidebarNavBtn:hover {{
        background-color: {surface_hover};
        color: {text_primary};
        border: 1px solid {border};
    }}

    QPushButton#SidebarNavBtn[active="true"] {{
        background-color: #1E3A8A;
        border: 1px solid {Colors.PRIMARY_BLUE};
        color: {Colors.NEON_BLUE};
        font-weight: 600;
    }}

    /* Buttons */
    QPushButton {{
        background-color: {surface_alt};
        border: 1px solid {border};
        border-radius: 6px;
        padding: 6px 14px;
        min-height: 28px;
        font-weight: 500;
        color: {text_primary};
    }}

    QPushButton:hover {{
        background-color: {surface_hover};
        border-color: {border_light};
    }}

    QPushButton:pressed {{
        background-color: {border};
    }}

    QPushButton:disabled {{
        background-color: {surface};
        color: {text_muted};
        border-color: {border};
    }}

    /* Table cell buttons override - ensures buttons inside tables never clip */
    QTableWidget QPushButton, QTableView QPushButton {{
        min-height: 0px;
        min-width: 0px;
        padding: 0px;
    }}

    /* Window Control Buttons (Title Bar) */
    QPushButton#WinMinBtn, QPushButton#WinMaxBtn {{
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 6px;
        color: #F8FAFC;
        font-size: 13px;
        font-weight: 700;
        padding: 0px;
        min-height: 26px;
    }}

    QPushButton#WinMinBtn:hover, QPushButton#WinMaxBtn:hover {{
        background-color: #334155;
        border-color: #60A5FA;
        color: #38BDF8;
    }}

    QPushButton#WinCloseBtn {{
        background-color: #7F1D1D;
        border: 1px solid #DC2626;
        border-radius: 6px;
        color: #FFFFFF;
        font-size: 13px;
        font-weight: 700;
        padding: 0px;
        min-height: 26px;
    }}

    QPushButton#WinCloseBtn:hover {{
        background-color: #DC2626;
        border-color: #EF4444;
        color: #FFFFFF;
    }}

    /* Primary Accent Button */
    QPushButton.PrimaryBtn, QPushButton#StartScanBtn {{
        background-color: {Colors.PRIMARY_BLUE};
        border: 1px solid {Colors.NEON_BLUE};
        color: #FFFFFF;
        font-weight: 600;
        padding: 7px 18px;
        min-height: 36px;
        border-radius: 6px;
    }}

    QPushButton.PrimaryBtn:hover, QPushButton#StartScanBtn:hover {{
        background-color: {Colors.PRIMARY_BLUE_HOVER};
        border-color: #60A5FA;
    }}

    /* Stop / Destructive Button */
    QPushButton.DangerBtn, QPushButton#StopScanBtn {{
        background-color: #991B1B;
        border: 1px solid {Colors.FAILED_RED};
        color: #FFFFFF;
        font-weight: 600;
        padding: 6px 12px;
        min-height: 28px;
        border-radius: 6px;
    }}

    QPushButton.DangerBtn:hover, QPushButton#StopScanBtn:hover {{
        background-color: #B91C1C;
    }}

    /* Warning / Pause Button */
    QPushButton.WarningBtn {{
        background-color: #854D0E;
        border: 1px solid {Colors.WARNING_AMBER};
        color: #FFFFFF;
        font-weight: 600;
        padding: 6px 12px;
        min-height: 28px;
        border-radius: 6px;
    }}

    QPushButton.WarningBtn:hover {{
        background-color: #A16207;
    }}

    /* Input Fields */
    QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
        background-color: {surface_alt};
        border: 1px solid {border};
        border-radius: 6px;
        padding: 6px 10px;
        min-height: 32px;
        color: {text_primary};
        selection-background-color: {Colors.PRIMARY_BLUE};
    }}

    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
        border: 1px solid {Colors.NEON_BLUE};
        background-color: {surface_hover};
    }}

    /* ComboBox */
    QComboBox {{
        background-color: {surface_alt};
        border: 1px solid {border};
        border-radius: 6px;
        padding: 4px 28px 4px 10px;
        min-height: 32px;
        color: {text_primary};
        min-width: 90px;
    }}

    QComboBox:hover {{
        border-color: {border_light};
        background-color: {surface_hover};
    }}

    QComboBox:focus {{
        border: 1px solid {Colors.NEON_BLUE};
    }}

    QComboBox::drop-down {{
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 24px;
        border-left: none;
    }}

    QComboBox::down-arrow {{
        width: 0px;
        height: 0px;
        border-left: 4px solid transparent;
        border-right: 4px solid transparent;
        border-top: 5px solid {text_sec};
        margin-right: 8px;
    }}

    QComboBox::down-arrow:hover {{
        border-top: 5px solid {Colors.NEON_BLUE};
    }}

    QComboBox QAbstractItemView {{
        background-color: {surface};
        border: 1px solid {border_light};
        border-radius: 6px;
        color: {text_primary};
        selection-background-color: {Colors.PRIMARY_BLUE};
        selection-color: #FFFFFF;
        padding: 4px;
    }}

    /* High Density Professional Results Table */
    QTableWidget, QTableView {{
        background-color: {surface};
        border: 1px solid {border};
        border-radius: 8px;
        gridline-color: {border};
        color: {text_primary};
        selection-background-color: #1E3A8A;
        selection-color: {text_primary};
        outline: none;
    }}

    QTableWidget::item, QTableView::item {{
        padding: 5px 8px;
        border-bottom: 1px solid {border};
    }}

    QTableWidget::item:hover, QTableView::item:hover {{
        background-color: {surface_hover};
    }}

    QTableWidget::item:selected, QTableView::item:selected {{
        background-color: #1E3A8A;
        color: {Colors.NEON_BLUE};
    }}

    QHeaderView::section {{
        background-color: {surface_alt};
        color: {text_sec};
        padding: 7px 10px;
        font-weight: 600;
        font-size: {font_size - 1}px;
        border: none;
        border-right: 1px solid {border};
        border-bottom: 2px solid {border_light};
    }}

    QHeaderView::section:hover {{
        background-color: {surface_hover};
        color: {text_primary};
    }}

    /* Progress Bar */
    QProgressBar {{
        background-color: {surface_alt};
        border: 1px solid {border};
        border-radius: 4px;
        height: 10px;
        text-align: center;
        color: transparent;
    }}

    QProgressBar::chunk {{
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {Colors.PRIMARY_BLUE}, stop:1 {Colors.NEON_BLUE});
        border-radius: 3px;
    }}

    /* Scrollbars */
    QScrollBar:vertical {{
        background-color: {surface};
        width: 10px;
        margin: 0px;
        border-radius: 5px;
    }}

    QScrollBar::handle:vertical {{
        background-color: {border_light};
        min-height: 25px;
        border-radius: 5px;
        margin: 2px;
    }}

    QScrollBar::handle:vertical:hover {{
        background-color: {Colors.NEON_BLUE};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QScrollBar:horizontal {{
        background-color: {surface};
        height: 10px;
        margin: 0px;
        border-radius: 5px;
    }}

    QScrollBar::handle:horizontal {{
        background-color: {border_light};
        min-width: 25px;
        border-radius: 5px;
        margin: 2px;
    }}

    QScrollBar::handle:horizontal:hover {{
        background-color: {Colors.NEON_BLUE};
    }}

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0px;
    }}

    /* Tab Widget */
    QTabWidget::pane {{
        border: 1px solid {border};
        border-radius: 8px;
        background-color: {surface};
    }}

    QTabBar::tab {{
        background-color: {surface_alt};
        border: 1px solid {border};
        border-bottom: none;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        padding: 7px 16px;
        margin-right: 3px;
        color: {text_sec};
        font-weight: 500;
    }}

    QTabBar::tab:selected {{
        background-color: {surface};
        color: {Colors.NEON_BLUE};
        border-top: 2px solid {Colors.NEON_BLUE};
        font-weight: 600;
    }}

    QTabBar::tab:hover:!selected {{
        background-color: {surface_hover};
        color: {text_primary};
    }}

    /* Context Menu */
    QMenu {{
        background-color: {surface};
        border: 1px solid {border_light};
        border-radius: 8px;
        padding: 5px;
    }}

    QMenu::item {{
        padding: 6px 20px 6px 12px;
        border-radius: 4px;
        color: {text_primary};
    }}

    QMenu::item:selected {{
        background-color: {Colors.PRIMARY_BLUE};
        color: #FFFFFF;
    }}

    QMenu::separator {{
        height: 1px;
        background-color: {border};
        margin: 4px 6px;
    }}

    /* Status Bar */
    QStatusBar {{
        background-color: {surface};
        border-top: 1px solid {border};
        color: {text_sec};
        padding: 4px 10px;
    }}

    /* Tooltip */
    QToolTip {{
        background-color: {surface_alt};
        color: {text_primary};
        border: 1px solid {Colors.NEON_BLUE};
        border-radius: 4px;
        padding: 4px 8px;
    }}
    """
