"""PySide6 Main Window for Network Sentry Desktop Application."""

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QStyle,
    QSystemTrayIcon,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.arp_scanner import ARPScanner, DiscoveryResult
from src.core.interface_detector import InterfaceDetector
from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, NetworkInterfaceInfo, SecurityAlertRecord
from src.gui.styles import DARK_THEME_QSS, RISK_COLORS, SEVERITY_COLORS
from src.gui.views.device_detail_dialog import DeviceDetailDialog
from src.native.c_bridge import NativePacketEngine
from src.security.arp_spoof_detector import ARPSpoofDetector
from src.security.port_scanner import PortScanner
from src.security.risk_engine import RiskEngine
from src.utils.config import ConfigManager
from src.utils.logger import setup_logger
from src.utils.notifier import SystemNotifier
from src.utils.reporter import ReportExporter

logger = setup_logger("MainWindow")


class DiscoveryScanWorker(QThread):
    """Background worker executing ARP discovery, spoofing analysis, and risk scoring."""

    progress_updated = Signal(int, int)
    scan_completed = Signal(object, list)
    scan_failed = Signal(str)

    def __init__(
        self,
        interface: NetworkInterfaceInfo,
        db: DatabaseManager,
        arp_scanner: ARPScanner,
        spoof_detector: ARPSpoofDetector,
        port_scanner: PortScanner,
        risk_engine: RiskEngine,
        alert_on_new_device: bool = True,
        auto_port_scan_new: bool = True,
        common_ports: Optional[List[int]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.interface = interface
        self.db = db
        self.arp_scanner = arp_scanner
        self.spoof_detector = spoof_detector
        self.port_scanner = port_scanner
        self.risk_engine = risk_engine
        self.alert_on_new_device = alert_on_new_device
        self.auto_port_scan_new = auto_port_scan_new
        self.common_ports = common_ports or [21, 22, 23, 80, 135, 139, 443, 445, 3389, 8080]

    def run(self) -> None:
        try:
            result = self.arp_scanner.scan_and_sync(
                interface=self.interface,
                db=self.db,
                alert_on_new_device=self.alert_on_new_device,
                progress_callback=lambda done, total: self.progress_updated.emit(done, total),
            )

            all_new_alerts: List[SecurityAlertRecord] = list(result.alerts_created)

            # 1. Analyze ARP table & mappings for ARP Spoofing / MITM
            spoof_alerts = self.spoof_detector.analyze_scan(
                ip_to_macs=result.ip_to_macs,
                devices=result.discovered_devices,
                gateway_ip=self.interface.gateway_ip,
                db=self.db,
            )
            all_new_alerts.extend(spoof_alerts)

            # 2. Optional quick port scan on newly discovered untrusted devices (limit to 3 per cycle)
            new_macs = {d.mac for d in result.new_devices}
            if self.auto_port_scan_new:
                untrusted_new = [d for d in result.new_devices if not d.is_trusted][:3]
                for ndev in untrusted_new:
                    self.port_scanner.scan_host(
                        ip=ndev.ip,
                        mac=ndev.mac,
                        ports=self.common_ports,
                        db=self.db,
                    )

            # 3. Evaluate risk score for all discovered devices
            unresolved = self.db.get_alerts(unresolved_only=True)
            for dev in result.discovered_devices:
                ports = self.db.get_device_ports(dev.mac)
                assessment = self.risk_engine.evaluate_device(
                    device=dev,
                    open_ports=ports,
                    active_alerts=unresolved,
                    is_new_device=(dev.mac in new_macs),
                    db=self.db,
                )
                all_new_alerts.extend(assessment.alerts)

            self.scan_completed.emit(result, all_new_alerts)
        except Exception as exc:
            logger.exception("DiscoveryScanWorker failed: %s", exc)
            self.scan_failed.emit(str(exc))


class MainWindow(QMainWindow):
    """Main desktop interface for Network Sentry."""

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        db: Optional[DatabaseManager] = None,
    ) -> None:
        super().__init__()
        self.cfg = config or ConfigManager("config.json")
        db_path = self.cfg.get("database", "path", "networksentry.db")
        wal_mode = bool(self.cfg.get("database", "wal_mode", True))
        self.db = db or DatabaseManager(db_path=db_path, wal_mode=wal_mode)

        self.arp_scanner = ARPScanner()
        self.spoof_detector = ARPSpoofDetector(
            lock_gateway_mac=bool(self.cfg.get("security", "lock_gateway_mac", True))
        )
        self.port_scanner = PortScanner(timeout=0.35, max_workers=24, grab_banners=True)
        self.risk_engine = RiskEngine()
        self.c_engine = NativePacketEngine(auto_compile=True)
        self.notifier = SystemNotifier(enabled=True)

        self.interfaces: List[NetworkInterfaceInfo] = InterfaceDetector.list_interfaces(
            include_loopback=False
        )
        self.active_interface: Optional[NetworkInterfaceInfo] = (
            self.interfaces[0] if self.interfaces else None
        )
        self._scan_worker: Optional[DiscoveryScanWorker] = None
        self._stat_labels: Dict[str, QLabel] = {}

        self.setWindowTitle("Network Sentry — LAN Discovery, Native C Packet Engine & Threat Monitor")
        self.resize(1260, 800)
        self.setStyleSheet(DARK_THEME_QSS)

        self._setup_ui()
        self._setup_tray_icon()
        self._setup_timers()
        self.refresh_all_views()

    def _create_app_icon(self) -> QIcon:
        """Create a clean shield/radar icon for window and system tray."""
        pix = QPixmap(32, 32)
        pix.fill(QColor("#0284C7"))
        return QIcon(pix)

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 14, 16, 12)
        main_layout.setSpacing(12)

        # 1. Header Bar
        header = QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(16, 10, 16, 10)
        header_layout.setSpacing(12)

        lbl_title = QLabel("NETWORK SENTRY")
        lbl_title.setObjectName("AppTitle")
        header_layout.addWidget(lbl_title)

        c_status = "C Engine: ACTIVE" if self.c_engine.is_native_loaded else "C Engine: Fallback"
        self.lbl_c_badge = QLabel(c_status)
        self.lbl_c_badge.setObjectName("EngineBadge")
        self.lbl_c_badge.setToolTip(self.c_engine.version())
        header_layout.addWidget(self.lbl_c_badge)

        header_layout.addWidget(QLabel("Interface:"))
        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(260)
        for iface in self.interfaces:
            gw_str = f" | GW: {iface.gateway_ip}" if iface.gateway_ip else ""
            self.combo_iface.addItem(f"{iface.name} ({iface.cidr}{gw_str})")
        self.combo_iface.currentIndexChanged.connect(self._on_interface_changed)
        header_layout.addWidget(self.combo_iface)

        self.chk_auto_scan = QCheckBox("Auto-Scan (s):")
        self.chk_auto_scan.setChecked(False)
        self.chk_auto_scan.toggled.connect(self._on_auto_scan_toggled)
        header_layout.addWidget(self.chk_auto_scan)

        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(10, 600)
        self.spin_interval.setValue(int(self.cfg.get("network", "scan_interval_seconds", 30)))
        self.spin_interval.valueChanged.connect(self._on_interval_changed)
        header_layout.addWidget(self.spin_interval)

        header_layout.addStretch()

        self.btn_scan_now = QPushButton("Scan Network Now")
        self.btn_scan_now.setObjectName("PrimaryButton")
        self.btn_scan_now.clicked.connect(self.start_network_scan)
        header_layout.addWidget(self.btn_scan_now)

        self.btn_sim_spoof = QPushButton("Simulate ARP Attack")
        self.btn_sim_spoof.setObjectName("DangerButton")
        self.btn_sim_spoof.setToolTip(
            "Craft a spoofed Gratuitous ARP packet via the Native C Engine to test real-time MITM detection"
        )
        self.btn_sim_spoof.clicked.connect(self.simulate_arp_spoofing_attack)
        header_layout.addWidget(self.btn_sim_spoof)

        self.btn_export_csv = QPushButton("Export CSV")
        self.btn_export_csv.clicked.connect(self.export_csv_report)
        header_layout.addWidget(self.btn_export_csv)

        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_json.clicked.connect(self.export_json_report)
        header_layout.addWidget(self.btn_export_json)

        main_layout.addWidget(header)

        # 2. Dashboard KPI Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        card_defs: List[Tuple[str, str, str]] = [
            ("total_devices", "TOTAL DEVICES", "#F8FAFC"),
            ("online_devices", "ONLINE NOW", "#10B981"),
            ("offline_devices", "OFFLINE", "#94A3B8"),
            ("trusted_devices", "TRUSTED", "#38BDF8"),
            ("high_risk_devices", "HIGH / CRITICAL RISK", "#F97316"),
            ("unresolved_alerts", "ACTIVE ALERTS", "#EF4444"),
        ]
        for key, title, color in card_defs:
            card = QFrame()
            card.setObjectName("StatCard")
            c_lay = QVBoxLayout(card)
            c_lay.setContentsMargins(14, 10, 14, 10)
            c_lay.setSpacing(4)

            lbl_t = QLabel(title)
            lbl_t.setObjectName("CardTitle")
            lbl_v = QLabel("0")
            lbl_v.setObjectName("CardValue")
            lbl_v.setStyleSheet(f"color: {color};")

            c_lay.addWidget(lbl_t)
            c_lay.addWidget(lbl_v)
            cards_layout.addWidget(card)
            self._stat_labels[key] = lbl_v

        main_layout.addLayout(cards_layout)

        # 3. Main Tab Widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, stretch=1)

        # --- Tab 1: Live Device Grid ---
        devices_tab = QWidget()
        dev_layout = QVBoxLayout(devices_tab)
        dev_layout.setContentsMargins(12, 12, 12, 12)
        dev_layout.setSpacing(10)

        filter_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Search devices by IP, MAC address, Vendor (Apple, Espressif...), or Hostname..."
        )
        self.search_input.textChanged.connect(self.refresh_devices_table)
        filter_row.addWidget(self.search_input, stretch=1)

        self.combo_filter = QComboBox()
        self.combo_filter.addItems(
            ["All Devices", "Online Only", "Untrusted Only", "High / Critical Risk"]
        )
        self.combo_filter.currentIndexChanged.connect(self.refresh_devices_table)
        filter_row.addWidget(self.combo_filter)

        self.btn_inspect = QPushButton("Inspect Device & Ports")
        self.btn_inspect.setObjectName("PrimaryButton")
        self.btn_inspect.clicked.connect(self.inspect_selected_device)
        filter_row.addWidget(self.btn_inspect)

        self.btn_toggle_trust = QPushButton("Toggle Trusted Status")
        self.btn_toggle_trust.setObjectName("SuccessButton")
        self.btn_toggle_trust.clicked.connect(self.toggle_selected_device_trust)
        filter_row.addWidget(self.btn_toggle_trust)

        dev_layout.addLayout(filter_row)

        self.devices_table = QTableWidget(0, 8)
        self.devices_table.setHorizontalHeaderLabels(
            [
                "Status",
                "IP Address",
                "MAC Address",
                "Vendor (OUI)",
                "Hostname",
                "Trust",
                "Risk Level",
                "Last Seen",
            ]
        )
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devices_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.devices_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.devices_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.devices_table.setAlternatingRowColors(True)
        self.devices_table.itemDoubleClicked.connect(lambda _: self.inspect_selected_device())
        dev_layout.addWidget(self.devices_table)

        self.tabs.addTab(devices_tab, "Live Network Devices")

        # --- Tab 2: Security Alerts Feed ---
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(alerts_tab)
        alerts_layout.setContentsMargins(12, 12, 12, 12)
        alerts_layout.setSpacing(10)

        alert_actions = QHBoxLayout()
        self.chk_unresolved_only = QCheckBox("Show Unresolved Alerts Only")
        self.chk_unresolved_only.setChecked(False)
        self.chk_unresolved_only.toggled.connect(self.refresh_alerts_table)
        alert_actions.addWidget(self.chk_unresolved_only)
        alert_actions.addStretch()

        self.btn_resolve_selected = QPushButton("Mark Selected Resolved")
        self.btn_resolve_selected.clicked.connect(self.resolve_selected_alert)
        alert_actions.addWidget(self.btn_resolve_selected)

        self.btn_resolve_all = QPushButton("Resolve All Alerts")
        self.btn_resolve_all.setObjectName("SuccessButton")
        self.btn_resolve_all.clicked.connect(self.resolve_all_alerts)
        alert_actions.addWidget(self.btn_resolve_all)

        alerts_layout.addLayout(alert_actions)

        self.alerts_table = QTableWidget(0, 7)
        self.alerts_table.setHorizontalHeaderLabels(
            ["ID", "Timestamp", "Severity", "Alert Type", "IP Address", "MAC Address", "Description"]
        )
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alerts_table.setAlternatingRowColors(True)
        alerts_layout.addWidget(self.alerts_table)

        self.tabs.addTab(alerts_tab, "Security Alerts Feed")

        # --- Tab 3: Device History Timeline ---
        history_tab = QWidget()
        hist_layout = QVBoxLayout(history_tab)
        hist_layout.setContentsMargins(12, 12, 12, 12)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(
            ["Timestamp", "Event Type", "MAC Address", "IP Address", "Details"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)
        hist_layout.addWidget(self.history_table)

        self.tabs.addTab(history_tab, "Device State History")

        # 4. Status Bar & Progress Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(220)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready. Click 'Scan Network Now' to discover active devices.")

    def _setup_tray_icon(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip("Network Sentry — LAN Security Monitor")

        tray_menu = QMenu(self)
        act_show = QAction("Show Window", self)
        act_show.triggered.connect(self.showNormal)
        act_scan = QAction("Scan Network Now", self)
        act_scan.triggered.connect(self.start_network_scan)
        act_quit = QAction("Exit", self)
        act_quit.triggered.connect(self.close)

        tray_menu.addAction(act_show)
        tray_menu.addAction(act_scan)
        tray_menu.addSeparator()
        tray_menu.addAction(act_quit)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.notifier.set_tray_icon(self.tray_icon)

    def _setup_timers(self) -> None:
        self.scan_timer = QTimer(self)
        self.scan_timer.timeout.connect(self.start_network_scan)

    def _on_interface_changed(self, index: int) -> None:
        if 0 <= index < len(self.interfaces):
            self.active_interface = self.interfaces[index]
            self.spoof_detector.reset_baseline()
            self.status_bar.showMessage(
                f"Switched active interface to {self.active_interface.name} ({self.active_interface.cidr})"
            )

    def _on_auto_scan_toggled(self, checked: bool) -> None:
        if checked:
            interval_ms = self.spin_interval.value() * 1000
            self.scan_timer.start(interval_ms)
            self.status_bar.showMessage(f"Auto-scan enabled (every {self.spin_interval.value()}s).")
        else:
            self.scan_timer.stop()
            self.status_bar.showMessage("Auto-scan paused.")

    def _on_interval_changed(self, seconds: int) -> None:
        if self.chk_auto_scan.isChecked():
            self.scan_timer.setInterval(seconds * 1000)

    def start_network_scan(self) -> None:
        """Launch an asynchronous ARP & Security scan on the active network interface."""
        if self._scan_worker is not None and self._scan_worker.isRunning():
            return
        if not self.active_interface:
            self.status_bar.showMessage("No active IPv4 network interface available.")
            return

        self.btn_scan_now.setEnabled(False)
        self.combo_iface.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage(
            f"Scanning subnet {self.active_interface.cidr} on {self.active_interface.name}..."
        )

        self._scan_worker = DiscoveryScanWorker(
            interface=self.active_interface,
            db=self.db,
            arp_scanner=self.arp_scanner,
            spoof_detector=self.spoof_detector,
            port_scanner=self.port_scanner,
            risk_engine=self.risk_engine,
            alert_on_new_device=bool(self.cfg.get("security", "alert_on_new_device", True)),
            auto_port_scan_new=bool(self.cfg.get("security", "auto_port_scan_new_devices", True)),
            common_ports=self.cfg.get("network", "common_ports"),
            parent=self,
        )
        self._scan_worker.progress_updated.connect(self._on_scan_progress)
        self._scan_worker.scan_completed.connect(self._on_scan_completed)
        self._scan_worker.scan_failed.connect(self._on_scan_failed)
        self._scan_worker.start()

    def _on_scan_progress(self, done: int, total: int) -> None:
        if total > 0:
            pct = int((done / total) * 100)
            self.progress_bar.setValue(pct)

    def _on_scan_completed(self, result: DiscoveryResult, new_alerts: List[SecurityAlertRecord]) -> None:
        self.btn_scan_now.setEnabled(True)
        self.combo_iface.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.refresh_all_views()

        for alert in new_alerts[:3]:
            self.notifier.notify_alert(alert)

        self.status_bar.showMessage(
            f"Scan complete in {result.duration_seconds:.2f}s — "
            f"{len(result.discovered_devices)} online, {len(result.new_devices)} new, "
            f"{len(new_alerts)} alert(s)."
        )

    def _on_scan_failed(self, error_msg: str) -> None:
        self.btn_scan_now.setEnabled(True)
        self.combo_iface.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage(f"Scan error: {error_msg}")

    def simulate_arp_spoofing_attack(self) -> None:
        """
        Simulate a live Gratuitous ARP Spoofing attack using the Native C Engine
        (`packet_parser.dll`) and verify that `ARPSpoofDetector` + `RiskEngine`
        immediately detect and escalate the threat.
        """
        gw_ip = (
            self.active_interface.gateway_ip
            if self.active_interface and self.active_interface.gateway_ip
            else "192.168.1.1"
        )
        if not self.spoof_detector.locked_gateway_mac:
            self.spoof_detector.set_gateway(gw_ip, "50:C7:BF:00:00:01")

        attacker_mac = "DE:AD:BE:EF:CA:FE"
        attacker_ip = "192.168.1.250"

        # 1. Build & Parse spoofed Ethernet + Gratuitous ARP Reply via Native C Engine
        raw_frame = self.c_engine.build_arp_frame(
            eth_dst="FF:FF:FF:FF:FF:FF",
            eth_src=attacker_mac,
            opcode=2,
            sender_mac=attacker_mac,
            sender_ip=gw_ip,
            target_mac="FF:FF:FF:FF:FF:FF",
            target_ip=gw_ip,
        )
        parsed = self.c_engine.parse_arp_packet(raw_frame)
        if parsed is None:
            return

        # 2. Register attacker device in DB
        attacker_dev = DeviceRecord(
            mac=parsed.src_mac,
            ip=attacker_ip,
            hostname="rogue-mitm-host",
            vendor="Randomized / Private MAC",
            is_online=True,
            is_trusted=False,
            notes="Simulated MITM Attacker via Native C Engine",
        )
        self.db.upsert_device(attacker_dev)

        # 3. Inspect parsed packet with ARPSpoofDetector
        alert = self.spoof_detector.inspect_arp_packet(
            src_mac=parsed.src_mac,
            src_ip=parsed.src_ip,
            dst_mac=parsed.dst_mac,
            dst_ip=parsed.dst_ip,
            opcode=parsed.opcode,
            is_gratuitous=parsed.is_gratuitous,
            eth_src_mac=parsed.eth_src_mac,
            mac_mismatch=parsed.mac_mismatch,
            db=self.db,
        )

        # 4. Update risk score to CRITICAL
        active_alerts = [alert] if alert else self.db.get_alerts(unresolved_only=True)
        self.risk_engine.evaluate_device(attacker_dev, active_alerts=active_alerts, db=self.db)

        if alert:
            self.notifier.notify_alert(alert)

        self.refresh_all_views()
        self.tabs.setCurrentIndex(1)  # Switch to Security Alerts Feed
        self.status_bar.showMessage(
            f"CRITICAL ALERT: Native C Engine parsed spoofed ARP reply from {parsed.src_mac} claiming Gateway {gw_ip}!"
        )

    def refresh_all_views(self) -> None:
        """Refresh dashboard counters, device grid, alerts feed, and history table."""
        stats = self.db.get_dashboard_stats()
        for key, lbl in self._stat_labels.items():
            lbl.setText(str(stats.get(key, 0)))

        self.refresh_devices_table()
        self.refresh_alerts_table()
        self.refresh_history_table()

    def refresh_devices_table(self) -> None:
        """Populate the live device grid applying current search and filter criteria."""
        all_devices = self.db.get_all_devices(online_only=False)
        query = self.search_input.text().strip().lower()
        mode = self.combo_filter.currentText()

        filtered: List[DeviceRecord] = []
        for dev in all_devices:
            if mode == "Online Only" and not dev.is_online:
                continue
            if mode == "Untrusted Only" and dev.is_trusted:
                continue
            if mode == "High / Critical Risk" and dev.risk_level not in ("HIGH", "CRITICAL"):
                continue

            if query:
                haystack = f"{dev.ip} {dev.mac} {dev.vendor} {dev.hostname} {dev.notes}".lower()
                if query not in haystack:
                    continue

            filtered.append(dev)

        self.devices_table.setRowCount(len(filtered))
        for row_idx, dev in enumerate(filtered):
            # Col 0: Status
            status_text = "● ONLINE" if dev.is_online else "○ OFFLINE"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor("#10B981" if dev.is_online else "#64748B"))
            status_item.setData(Qt.ItemDataRole.UserRole, dev.mac)
            self.devices_table.setItem(row_idx, 0, status_item)

            # Col 1: IP
            self.devices_table.setItem(row_idx, 1, QTableWidgetItem(dev.ip))

            # Col 2: MAC
            mac_item = QTableWidgetItem(dev.mac)
            mac_item.setForeground(QColor("#93C5FD"))
            self.devices_table.setItem(row_idx, 2, mac_item)

            # Col 3: Vendor
            self.devices_table.setItem(row_idx, 3, QTableWidgetItem(dev.vendor))

            # Col 4: Hostname
            self.devices_table.setItem(row_idx, 4, QTableWidgetItem(dev.hostname))

            # Col 5: Trust
            trust_text = "Trusted" if dev.is_trusted else "Untrusted"
            trust_item = QTableWidgetItem(trust_text)
            trust_item.setForeground(QColor("#38BDF8" if dev.is_trusted else "#F59E0B"))
            self.devices_table.setItem(row_idx, 5, trust_item)

            # Col 6: Risk Level
            risk_text = f"{dev.risk_level} ({dev.risk_score})"
            risk_item = QTableWidgetItem(risk_text)
            risk_color = RISK_COLORS.get(dev.risk_level, "#10B981")
            risk_item.setForeground(QColor(risk_color))
            self.devices_table.setItem(row_idx, 6, risk_item)

            # Col 7: Last Seen
            self.devices_table.setItem(row_idx, 7, QTableWidgetItem(dev.last_seen))

    def refresh_alerts_table(self) -> None:
        """Populate the security alerts feed table."""
        unresolved_only = self.chk_unresolved_only.isChecked()
        alerts = self.db.get_alerts(limit=200, unresolved_only=unresolved_only)
        self.alerts_table.setRowCount(len(alerts))

        for row_idx, alert in enumerate(alerts):
            id_item = QTableWidgetItem(str(alert.id or ""))
            id_item.setData(Qt.ItemDataRole.UserRole, alert.id)
            self.alerts_table.setItem(row_idx, 0, id_item)
            self.alerts_table.setItem(row_idx, 1, QTableWidgetItem(alert.timestamp))

            sev_item = QTableWidgetItem(alert.severity)
            sev_color = SEVERITY_COLORS.get(alert.severity, "#E2E8F0")
            sev_item.setForeground(QColor(sev_color))
            self.alerts_table.setItem(row_idx, 2, sev_item)

            type_text = alert.alert_type + (" [RESOLVED]" if alert.is_resolved else "")
            self.alerts_table.setItem(row_idx, 3, QTableWidgetItem(type_text))
            self.alerts_table.setItem(row_idx, 4, QTableWidgetItem(alert.ip))
            self.alerts_table.setItem(row_idx, 5, QTableWidgetItem(alert.mac))
            self.alerts_table.setItem(row_idx, 6, QTableWidgetItem(alert.description))

    def refresh_history_table(self) -> None:
        """Populate the device history timeline table."""
        history = self.db.get_device_history(limit=150)
        self.history_table.setRowCount(len(history))
        for row_idx, h in enumerate(history):
            self.history_table.setItem(row_idx, 0, QTableWidgetItem(h.timestamp))
            self.history_table.setItem(row_idx, 1, QTableWidgetItem(h.event_type))
            self.history_table.setItem(row_idx, 2, QTableWidgetItem(h.mac))
            self.history_table.setItem(row_idx, 3, QTableWidgetItem(h.ip))
            self.history_table.setItem(row_idx, 4, QTableWidgetItem(h.details))

    def _get_selected_device(self) -> Optional[DeviceRecord]:
        row = self.devices_table.currentRow()
        if row < 0:
            return None
        status_item = self.devices_table.item(row, 0)
        if not status_item:
            return None
        mac = status_item.data(Qt.ItemDataRole.UserRole)
        if not mac:
            return None
        return self.db.get_device_by_mac(str(mac))

    def inspect_selected_device(self) -> None:
        """Open the DeviceDetailDialog for the currently selected device."""
        dev = self._get_selected_device()
        if not dev:
            QMessageBox.information(self, "Select Device", "Please select a device row first.")
            return
        dlg = DeviceDetailDialog(device=dev, db=self.db, parent=self)
        dlg.device_updated.connect(lambda _: self.refresh_all_views())
        dlg.exec()
        self.refresh_all_views()

    def toggle_selected_device_trust(self) -> None:
        """Toggle the trusted status of the selected device and recalculate its risk."""
        dev = self._get_selected_device()
        if not dev:
            return
        new_trust = not dev.is_trusted
        self.db.set_device_trusted(dev.mac, new_trust)
        dev.is_trusted = new_trust

        ports = self.db.get_device_ports(dev.mac)
        alerts = self.db.get_alerts(unresolved_only=True)
        self.risk_engine.evaluate_device(dev, open_ports=ports, active_alerts=alerts, db=self.db)
        self.refresh_all_views()

    def _recalculate_all_device_risks(self) -> None:
        """Re-evaluate risk scores for all devices against remaining unresolved alerts."""
        unresolved = self.db.get_alerts(unresolved_only=True)
        for dev in self.db.get_all_devices(online_only=False):
            ports = self.db.get_device_ports(dev.mac)
            self.risk_engine.evaluate_device(
                dev,
                open_ports=ports,
                active_alerts=unresolved,
                db=self.db,
            )

    def resolve_selected_alert(self) -> None:
        """Mark the currently selected security alert as resolved and update device risk scores."""
        row = self.alerts_table.currentRow()
        if row < 0:
            return
        id_item = self.alerts_table.item(row, 0)
        if not id_item:
            return
        alert_id = id_item.data(Qt.ItemDataRole.UserRole)
        if alert_id is not None:
            self.db.resolve_alert(int(alert_id))
            self._recalculate_all_device_risks()
            self.refresh_all_views()

    def resolve_all_alerts(self) -> None:
        """Mark all unresolved security alerts as resolved and update device risk scores."""
        count = self.db.resolve_all_alerts()
        self._recalculate_all_device_risks()
        self.refresh_all_views()
        self.status_bar.showMessage(f"Resolved {count} alert(s).")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        """Stop background timers, wait for active worker thread, and hide tray icon on exit."""
        if hasattr(self, "scan_timer"):
            self.scan_timer.stop()
        if self._scan_worker is not None and self._scan_worker.isRunning():
            self._scan_worker.wait(2500)
        if hasattr(self, "tray_icon") and self.tray_icon is not None:
            self.tray_icon.hide()
        super().closeEvent(event)

    def export_csv_report(self, target_path: Optional[str | Path] = None) -> Optional[Path]:
        """Export current device inventory to a CSV file."""
        if target_path is None:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Devices CSV Report",
                "networksentry_devices.csv",
                "CSV Files (*.csv)",
            )
            if not file_path:
                return None
            target_path = file_path

        devices = self.db.get_all_devices(online_only=False)
        out = ReportExporter.export_devices_csv(devices, target_path)
        self.status_bar.showMessage(f"Exported {len(devices)} device(s) to {out}")
        return out

    def export_json_report(self, target_path: Optional[str | Path] = None) -> Optional[Path]:
        """Export full security audit report to a JSON file."""
        if target_path is None:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Full Security Audit JSON Report",
                "networksentry_audit_report.json",
                "JSON Files (*.json)",
            )
            if not file_path:
                return None
            target_path = file_path

        out = ReportExporter.export_full_report_json(
            db=self.db,
            output_path=target_path,
            interface=self.active_interface,
        )
        self.status_bar.showMessage(f"Exported full JSON audit report to {out}")
        return out
