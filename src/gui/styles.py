"""Modern Dark Cybersecurity Theme QSS and color palette for PySide6 GUI."""

DARK_THEME_QSS = """
QMainWindow, QDialog {
    background-color: #0B0F19;
    color: #E2E8F0;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QWidget {
    color: #E2E8F0;
    font-family: "Segoe UI", "Inter", sans-serif;
}

QFrame#HeaderBar {
    background-color: #111827;
    border-bottom: 1px solid #1E293B;
    border-radius: 8px;
}

QFrame#StatCard {
    background-color: #111827;
    border: 1px solid #1E293B;
    border-radius: 10px;
}

QLabel#CardTitle {
    color: #94A3B8;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
}

QLabel#CardValue {
    color: #F8FAFC;
    font-size: 24px;
    font-weight: 700;
}

QLabel#AppTitle {
    color: #38BDF8;
    font-size: 19px;
    font-weight: 800;
}

QLabel#EngineBadge {
    background-color: #064E3B;
    color: #34D399;
    border: 1px solid #059669;
    border-radius: 6px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 700;
}

QPushButton {
    background-color: #1E293B;
    color: #F1F5F9;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #0F172A;
}

QPushButton:disabled {
    background-color: #0F172A;
    color: #475569;
    border-color: #1E293B;
}

QPushButton#PrimaryButton {
    background-color: #0284C7;
    color: #FFFFFF;
    border: 1px solid #0369A1;
}

QPushButton#PrimaryButton:hover {
    background-color: #0369A1;
}

QPushButton#DangerButton {
    background-color: #991B1B;
    color: #FEE2E2;
    border: 1px solid #DC2626;
}

QPushButton#DangerButton:hover {
    background-color: #B91C1C;
}

QPushButton#SuccessButton {
    background-color: #065F46;
    color: #D1FAE5;
    border: 1px solid #059669;
}

QPushButton#SuccessButton:hover {
    background-color: #047857;
}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background-color: #0F172A;
    color: #F8FAFC;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 5px 10px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border: 1px solid #38BDF8;
}

QTabWidget::pane {
    border: 1px solid #1E293B;
    background-color: #111827;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: #0F172A;
    color: #94A3B8;
    border: 1px solid #1E293B;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 18px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #1E293B;
    color: #38BDF8;
    border-color: #334155;
}

QTableWidget {
    background-color: #0F172A;
    alternate-background-color: #111827;
    color: #E2E8F0;
    gridline-color: #1E293B;
    border: 1px solid #1E293B;
    border-radius: 6px;
    selection-background-color: #1E3A8A;
    selection-color: #FFFFFF;
}

QHeaderView::section {
    background-color: #1E293B;
    color: #94A3B8;
    font-weight: 700;
    font-size: 12px;
    padding: 7px 10px;
    border: none;
    border-right: 1px solid #0F172A;
    border-bottom: 1px solid #334155;
}

QProgressBar {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 5px;
    text-align: center;
    color: #F8FAFC;
    font-weight: 600;
}

QProgressBar::chunk {
    background-color: #0284C7;
    border-radius: 4px;
}

QStatusBar {
    background-color: #090D16;
    color: #94A3B8;
    border-top: 1px solid #1E293B;
}
"""

RISK_COLORS = {
    "LOW": "#10B981",       # Emerald Green
    "MEDIUM": "#F59E0B",    # Amber Yellow
    "HIGH": "#F97316",      # Orange
    "CRITICAL": "#EF4444",  # Crimson Red
}

SEVERITY_COLORS = {
    "INFO": "#38BDF8",
    "WARNING": "#F59E0B",
    "CRITICAL": "#EF4444",
}
