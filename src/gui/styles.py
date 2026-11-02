"""Cyber Guardian (Gold/Amber & Obsidian) and Deep Telemetry QSS theme for PySide6 GUI."""

DARK_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #0D0F14;
    color: #E2E8F0;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QWidget {
    color: #E2E8F0;
    font-family: "Segoe UI", "Inter", sans-serif;
}

/* Top Navigation Header Bar (Photo 1) */
QFrame#TopNavBar {
    background-color: #13161F;
    border-bottom: 1px solid #2A2E3B;
}

QLabel#BrandTitle {
    color: #F8FAFC;
    font-size: 15px;
    font-weight: 800;
    letter-spacing: 0.8px;
}

QLabel#BrandSubtitle {
    color: #94A3B8;
    font-size: 13px;
    font-weight: 500;
}

QPushButton#NavTabButton {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-bottom: 2px solid transparent;
    border-radius: 0px;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#NavTabButton:hover {
    color: #FDE68A;
}

QPushButton#NavTabButton[active="true"] {
    color: #F8FAFC;
    border-bottom: 2px solid #F59E0B;
    font-weight: 700;
}

/* Left Vertical Icon Sidebar (Photo 1) */
QFrame#LeftSidebar {
    background-color: #12151E;
    border-right: 1px solid #262A36;
}

QPushButton#SidebarIconBtn {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 700;
    padding: 10px 0px;
}

QPushButton#SidebarIconBtn:hover {
    background-color: #1C202E;
    color: #FBBF24;
}

QPushButton#SidebarIconBtn[active="true"] {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(245, 158, 11, 55), stop:1 rgba(245, 158, 11, 8));
    color: #FBBF24;
    border-left: 3px solid #F59E0B;
}

/* Top KPI Status Strip (Photo 1) */
QFrame#StatusStripBar {
    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1B1F2A, stop:1 #13161E);
    border: 1px solid #2E3342;
    border-radius: 10px;
}

QFrame#KpiCell {
    background-color: transparent;
    border-right: 1px solid #282C3A;
}

QLabel#KpiLabel {
    color: #94A3B8;
    font-size: 11px;
    font-weight: 500;
}

QLabel#KpiValueWhite {
    color: #F8FAFC;
    font-size: 18px;
    font-weight: 800;
}

QLabel#KpiValueActive {
    color: #22C55E;
    font-size: 16px;
    font-weight: 800;
}

QLabel#KpiValueElevated {
    color: #F59E0B;
    font-size: 16px;
    font-weight: 800;
}

/* Dashboard Cards (Photo 1 & Photo 2) */
QFrame#CyberCard {
    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1C202B, stop:1 #13161F);
    border: 1px solid #2C3140;
    border-radius: 12px;
}

QFrame#CyberCardGold {
    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1D212C, stop:1 #13161F);
    border: 1px solid #4A3B22;
    border-bottom: 2px solid #D97706;
    border-radius: 12px;
}

QFrame#TelemetryPanel {
    background-color: #14171F;
    border: 1px solid #242936;
    border-radius: 6px;
}

QFrame#HeaderBar, QFrame#StatCard {
    background-color: #151922;
    border: 1px solid #282D3B;
    border-radius: 10px;
}

QLabel#CardHeaderTitle {
    color: #F8FAFC;
    font-size: 14px;
    font-weight: 700;
}

QLabel#CardTitle {
    color: #94A3B8;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.4px;
}

QLabel#CardValue {
    color: #F8FAFC;
    font-size: 24px;
    font-weight: 800;
}

QLabel#StatHugeWhite {
    color: #F8FAFC;
    font-size: 30px;
    font-weight: 800;
}

QLabel#StatHugeGold {
    color: #FBBF24;
    font-size: 28px;
    font-weight: 800;
}

QLabel#AppTitle {
    color: #FBBF24;
    font-size: 18px;
    font-weight: 800;
}

QLabel#EngineBadge {
    background-color: #2A2111;
    color: #FBBF24;
    border: 1px solid #D97706;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 700;
}

/* Alert Banner & Rows (Photo 1 Active Alerts) */
QFrame#HighPriorityBanner {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #351A1E, stop:1 #1E1C26);
    border: 1px solid #5C282D;
    border-radius: 7px;
}

QFrame#AlertItemCard {
    background-color: #181B24;
    border: 1px solid #282D3C;
    border-radius: 7px;
}

QFrame#AlertItemCard:hover {
    background-color: #202431;
    border-color: #F59E0B;
}

/* Buttons */
QPushButton {
    background-color: #1C202B;
    color: #F1F5F9;
    border: 1px solid #323846;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #282E3D;
    border-color: #F59E0B;
}

QPushButton:pressed {
    background-color: #12151E;
}

QPushButton:disabled {
    background-color: #12151E;
    color: #475569;
    border-color: #1E2430;
}

/* Gold 'Start Scan' CTA Button (Photo 1) */
QPushButton#GoldScanButton, QPushButton#PrimaryButton {
    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FDE047, stop:0.5 #F59E0B, stop:1 #D97706);
    color: #111318;
    border: 1px solid #FEF08A;
    border-radius: 7px;
    padding: 7px 18px;
    font-size: 13px;
    font-weight: 800;
}

QPushButton#GoldScanButton:hover, QPushButton#PrimaryButton:hover {
    background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FEF08A, stop:0.5 #FBBF24, stop:1 #EA580C);
    border-color: #FFFFFF;
}

QPushButton#CyanRefreshButton {
    background-color: #0F172A;
    color: #38BDF8;
    border: 1px solid #0284C7;
    border-radius: 12px;
    padding: 5px 16px;
    font-size: 11px;
    font-weight: 800;
}

QPushButton#CyanRefreshButton:hover {
    background-color: #0369A1;
    color: #FFFFFF;
}

QPushButton#DangerButton {
    background-color: #3B1219;
    color: #FCA5A5;
    border: 1px solid #DC2626;
}

QPushButton#DangerButton:hover {
    background-color: #7F1D1D;
    color: #FFFFFF;
}

QPushButton#SuccessButton {
    background-color: #063E2E;
    color: #6EE7B7;
    border: 1px solid #059669;
}

QPushButton#SuccessButton:hover {
    background-color: #047857;
    color: #FFFFFF;
}

/* Inputs & Dropdowns */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background-color: #141821;
    color: #F8FAFC;
    border: 1px solid #2E3444;
    border-radius: 6px;
    padding: 5px 10px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border: 1px solid #F59E0B;
}

QComboBox::drop-down {
    border: none;
    width: 22px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #262B38;
    background-color: #12151E;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #12151E;
    color: #94A3B8;
    border: 1px solid #262B38;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 7px 16px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #1C202B;
    color: #FBBF24;
    border-color: #F59E0B;
}

/* Tables */
QTableWidget {
    background-color: #12151E;
    alternate-background-color: #161A25;
    color: #E2E8F0;
    gridline-color: #222634;
    border: 1px solid #262B38;
    border-radius: 7px;
    selection-background-color: #3B2F16;
    selection-color: #FDE68A;
}

QHeaderView::section {
    background-color: #191D28;
    color: #94A3B8;
    font-weight: 700;
    font-size: 11px;
    padding: 7px 10px;
    border: none;
    border-right: 1px solid #12151E;
    border-bottom: 1px solid #2C3242;
}

/* Timeline Slider (Photo 1 Bottom Bar) */
QSlider::groove:horizontal {
    height: 4px;
    background: #282D3B;
    border-radius: 2px;
}

QSlider::sub-page:horizontal {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #92400E, stop:1 #FBBF24);
    border-radius: 2px;
}

QSlider::handle:horizontal {
    background: #FDE047;
    border: 2px solid #D97706;
    width: 14px;
    height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}

QProgressBar {
    background-color: #191D28;
    border: 1px solid #2E3444;
    border-radius: 5px;
    text-align: center;
    color: #F8FAFC;
    font-weight: 700;
}

QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #D97706, stop:1 #FBBF24);
    border-radius: 4px;
}

QStatusBar {
    background-color: #0B0D12;
    color: #94A3B8;
    border-top: 1px solid #222634;
}
"""

RISK_COLORS = {
    "LOW": "#10B981",       # Emerald Green
    "MEDIUM": "#F59E0B",    # Amber Gold
    "HIGH": "#F97316",      # Warm Orange
    "CRITICAL": "#EF4444",  # Crimson Red
}

SEVERITY_COLORS = {
    "INFO": "#38BDF8",
    "WARNING": "#F59E0B",
    "CRITICAL": "#EF4444",
}
