"""Detailed device inspection, port analysis, and history dialog."""

from typing import List, Optional

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, PortScanRecord
from src.gui.styles import DARK_THEME_QSS, RISK_COLORS
from src.gui.widgets.cyber_charts import create_cyber_guardian_icon
from src.security.port_scanner import DEFAULT_SCAN_PORTS, PortScanner
from src.security.risk_engine import RiskEngine


class SingleHostPortScanWorker(QThread):
    """Background worker thread for scanning TCP ports on a single device."""

    scan_finished = Signal(list)

    def __init__(
        self,
        ip: str,
        mac: str,
        db: DatabaseManager,
        ports: Optional[List[int]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.ip = ip
        self.mac = mac
        self.db = db
        self.ports = ports or DEFAULT_SCAN_PORTS

    def run(self) -> None:
        scanner = PortScanner(timeout=0.45, max_workers=24, grab_banners=True)
        open_ports = scanner.scan_host(self.ip, mac=self.mac, ports=self.ports, db=self.db)
        dev = self.db.get_device_by_mac(self.mac)
        if dev:
            alerts = self.db.get_alerts(unresolved_only=True)
            RiskEngine().evaluate_device(dev, open_ports=open_ports, active_alerts=alerts, db=self.db)
        self.scan_finished.emit(open_ports)


class DeviceDetailDialog(QDialog):
    """Modal dialog showing device metadata, open TCP ports, and connection history."""

    device_updated = Signal(str)

    def __init__(
        self,
        device: DeviceRecord,
        db: DatabaseManager,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.device = device
        self.db = db
        self._scan_worker: Optional[SingleHostPortScanWorker] = None

        self.setWindowTitle(f"Cyber Guardian Inspector — {device.ip} ({device.mac})")
        self.setWindowIcon(create_cyber_guardian_icon(32))
        self.setStyleSheet(DARK_THEME_QSS)
        self.resize(780, 620)
        self._build_ui()
        self.refresh_data()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Top Summary Card
        info_frame = QFrame()
        info_frame.setObjectName("StatCard")
        form = QFormLayout(info_frame)
        form.setContentsMargins(14, 14, 14, 14)
        form.setSpacing(8)

        self.lbl_mac = QLabel(self.device.mac)
        self.lbl_ip = QLabel(self.device.ip)
        self.lbl_vendor = QLabel(self.device.vendor)
        self.lbl_seen = QLabel(f"First: {self.device.first_seen}  |  Last: {self.device.last_seen}")
        self.lbl_risk = QLabel(f"{self.device.risk_level} (Score: {self.device.risk_score}/100)")

        self.edit_hostname = QLineEdit(self.device.hostname)
        self.edit_notes = QLineEdit(self.device.notes)
        self.edit_notes.setPlaceholderText("Add custom device label or security notes...")
        self.chk_trusted = QCheckBox("Trusted Device (Whitelist)")
        self.chk_trusted.setChecked(self.device.is_trusted)

        form.addRow("MAC Address:", self.lbl_mac)
        form.addRow("IPv4 Address:", self.lbl_ip)
        form.addRow("Hardware Vendor:", self.lbl_vendor)
        form.addRow("Activity Window:", self.lbl_seen)
        form.addRow("Security Risk:", self.lbl_risk)
        form.addRow("Hostname:", self.edit_hostname)
        form.addRow("Custom Notes:", self.edit_notes)
        form.addRow("Trust Status:", self.chk_trusted)

        layout.addWidget(info_frame)

        # 2. Action Bar
        btn_row = QHBoxLayout()
        self.btn_save = QPushButton("Save Changes")
        self.btn_save.setObjectName("SuccessButton")
        self.btn_save.clicked.connect(self._on_save_changes)

        self.btn_port_scan = QPushButton("Scan TCP Ports & Banners Now")
        self.btn_port_scan.setObjectName("PrimaryButton")
        self.btn_port_scan.clicked.connect(self._on_start_port_scan)

        self.lbl_scan_status = QLabel("")
        btn_row.addWidget(self.btn_save)
        btn_row.addWidget(self.btn_port_scan)
        btn_row.addWidget(self.lbl_scan_status)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # 3. Open TCP Ports Table
        layout.addWidget(QLabel("Discovered Open TCP Ports & Service Banners:"))
        self.ports_table = QTableWidget(0, 5)
        self.ports_table.setHorizontalHeaderLabels(
            ["Port", "Protocol", "Service", "Banner / Version", "Scanned At"]
        )
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.ports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ports_table.setAlternatingRowColors(True)
        layout.addWidget(self.ports_table)

        # 4. Device History Table
        layout.addWidget(QLabel("Device State History (IP Changes / Online-Offline Transitions):"))
        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(["Timestamp", "Event Type", "IP Address", "Details"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)
        layout.addWidget(self.history_table)

    def refresh_data(self) -> None:
        """Reload latest device record, open ports, and history from SQLite."""
        latest = self.db.get_device_by_mac(self.device.mac)
        if latest:
            self.device = latest

        color_hex = RISK_COLORS.get(self.device.risk_level, "#10B981")
        self.lbl_risk.setText(f"{self.device.risk_level} (Score: {self.device.risk_score}/100)")
        self.lbl_risk.setStyleSheet(f"color: {color_hex}; font-weight: bold;")

        ports = self.db.get_device_ports(self.device.mac)
        self._populate_ports(ports)

        history = self.db.get_device_history(self.device.mac, limit=50)
        self.history_table.setRowCount(len(history))
        for row_idx, h in enumerate(history):
            self.history_table.setItem(row_idx, 0, QTableWidgetItem(h.timestamp))
            self.history_table.setItem(row_idx, 1, QTableWidgetItem(h.event_type))
            self.history_table.setItem(row_idx, 2, QTableWidgetItem(h.ip))
            self.history_table.setItem(row_idx, 3, QTableWidgetItem(h.details))

    def _populate_ports(self, ports: List[PortScanRecord]) -> None:
        self.ports_table.setRowCount(len(ports))
        for row_idx, p in enumerate(ports):
            port_item = QTableWidgetItem(str(p.port))
            port_item.setForeground(QColor("#38BDF8"))
            self.ports_table.setItem(row_idx, 0, port_item)
            self.ports_table.setItem(row_idx, 1, QTableWidgetItem(p.protocol))
            self.ports_table.setItem(row_idx, 2, QTableWidgetItem(p.service))
            self.ports_table.setItem(row_idx, 3, QTableWidgetItem(p.banner or "—"))
            self.ports_table.setItem(row_idx, 4, QTableWidgetItem(p.scanned_at))

    def _on_save_changes(self) -> None:
        trusted = self.chk_trusted.isChecked()
        hostname = self.edit_hostname.text().strip() or "Unknown"
        notes = self.edit_notes.text().strip()

        self.db.set_device_trusted(self.device.mac, trusted)
        self.db.update_device_notes(self.device.mac, notes=notes, hostname=hostname)

        dev = self.db.get_device_by_mac(self.device.mac)
        if dev:
            ports = self.db.get_device_ports(self.device.mac)
            alerts = self.db.get_alerts(unresolved_only=True)
            RiskEngine().evaluate_device(dev, open_ports=ports, active_alerts=alerts, db=self.db)

        self.refresh_data()
        self.device_updated.emit(self.device.mac)
        self.lbl_scan_status.setText("Saved!")

    def _on_start_port_scan(self) -> None:
        if self._scan_worker is not None and self._scan_worker.isRunning():
            return
        self.btn_port_scan.setEnabled(False)
        self.lbl_scan_status.setText(f"Scanning {len(DEFAULT_SCAN_PORTS)} TCP ports on {self.device.ip}...")
        self._scan_worker = SingleHostPortScanWorker(
            ip=self.device.ip,
            mac=self.device.mac,
            db=self.db,
            parent=self,
        )
        self._scan_worker.scan_finished.connect(self._on_port_scan_done)
        self._scan_worker.start()

    def _on_port_scan_done(self, open_ports: List[PortScanRecord]) -> None:
        self.btn_port_scan.setEnabled(True)
        self.lbl_scan_status.setText(f"Scan complete: {len(open_ports)} open TCP port(s) found.")
        self.refresh_data()
        self.device_updated.emit(self.device.mac)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Ensure background port scan worker completes cleanly before closing dialog."""
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._scan_worker.wait(2000)
        super().closeEvent(event)
