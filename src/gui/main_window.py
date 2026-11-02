"""PySide6 Main Window for Cyber Guardian / Network Sentry Desktop Application."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QAction, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSlider,
    QSpinBox,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from src.core.arp_scanner import ARPScanner, DiscoveryResult
from src.core.interface_detector import InterfaceDetector
from src.core.traffic_monitor import TelemetrySnapshot, TrafficMonitor
from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, NetworkInterfaceInfo, SecurityAlertRecord
from src.gui.styles import DARK_THEME_QSS, RISK_COLORS, SEVERITY_COLORS
from src.gui.views.device_detail_dialog import DeviceDetailDialog
from src.gui.widgets.cyber_charts import (
    FlowsSpiralWidget,
    HorizontalBreakdownBarWidget,
    PortOverviewGaugeWidget,
    RealtimePacketFlowChart,
    ShieldLogoWidget,
    TcpFlagDistributionWidget,
    TelemetryAreaChart,
    TimelineScrubberSlider,
    TopProtocolsBarChart,
    create_cyber_guardian_icon,
)
from src.native.c_bridge import NativePacketEngine
from src.security.arp_spoof_detector import ARPSpoofDetector
from src.security.port_scanner import PortScanner
from src.security.risk_engine import RiskEngine
from src.utils.config import ConfigManager
from src.utils.logger import setup_logger
from src.utils.notifier import SystemNotifier
from src.utils.oui_lookup import OUILookup
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

            # 2. Quick port scan on newly discovered untrusted devices (limit to 3 per cycle)
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
    """
    Main desktop interface replicating the Cyber Guardian Dashboard (Photo 1)
    and Deep Traffic Overview Telemetry (Photo 2).
    """

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
        self.traffic_monitor = TrafficMonitor(
            max_samples=60,
            demo_mode=False,
            c_engine=self.c_engine,
        )

        self.interfaces: List[NetworkInterfaceInfo] = InterfaceDetector.list_interfaces(
            include_loopback=False
        )
        self.active_interface: Optional[NetworkInterfaceInfo] = (
            self.interfaces[0] if self.interfaces else None
        )
        self._ensure_local_host_seeded()

        self._scan_worker: Optional[DiscoveryScanWorker] = None
        self._stat_labels: Dict[str, QLabel] = {}
        self._nav_buttons: List[QPushButton] = []
        self._side_buttons: List[QPushButton] = []
        self._telemetry_charts: List[TelemetryAreaChart] = []

        self.setWindowTitle("CYBER GUARDIAN | Network Port Scanner & Packet Analyzer")
        self.setWindowIcon(create_cyber_guardian_icon(64))
        self.resize(1380, 860)
        self.setStyleSheet(DARK_THEME_QSS)

        self._setup_ui()
        self._setup_tray_icon()
        self._setup_timers()
        self.refresh_all_views()

    def _ensure_local_host_seeded(self) -> None:
        """Ensure the local machine is registered in SQLite if DB is completely empty."""
        try:
            if self.db.get_dashboard_stats()["total_devices"] == 0 and self.active_interface:
                iface = self.active_interface
                if iface.mac_address and iface.mac_address != "00:00:00:00:00:00":
                    oui = OUILookup()
                    vendor = oui.lookup(iface.mac_address)
                    if vendor == "Unknown Vendor":
                        vendor = "Local Host (This PC)"
                    self.db.upsert_device(
                        DeviceRecord(
                            mac=iface.mac_address,
                            ip=iface.ip_address,
                            hostname=socket.gethostname(),
                            vendor=vendor,
                            is_online=True,
                            is_trusted=True,
                            risk_level="LOW",
                            risk_score=0,
                            notes=f"Primary interface: {iface.name}",
                        )
                    )
        except Exception as exc:
            logger.debug("Local host seeding skipped: %s", exc)

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_vbox = QVBoxLayout(central)
        root_vbox.setContentsMargins(0, 0, 0, 0)
        root_vbox.setSpacing(0)

        # =====================================================================
        # 1. TOP NAVIGATION BAR (Photo 1: Shield + CYBER GUARDIAN + Nav Tabs)
        # =====================================================================
        top_bar = QFrame()
        top_bar.setObjectName("TopNavBar")
        top_bar.setFixedHeight(52)
        top_lay = QHBoxLayout(top_bar)
        top_lay.setContentsMargins(16, 0, 18, 0)
        top_lay.setSpacing(12)

        top_lay.addWidget(ShieldLogoWidget(size=28))

        lbl_brand = QLabel("CYBER GUARDIAN")
        lbl_brand.setObjectName("BrandTitle")
        top_lay.addWidget(lbl_brand)

        lbl_sep = QLabel("|")
        lbl_sep.setStyleSheet("color: #334155; font-size: 16px;")
        top_lay.addWidget(lbl_sep)

        lbl_sub = QLabel("Network Port Scanner & Packet Analyzer")
        lbl_sub.setObjectName("BrandSubtitle")
        top_lay.addWidget(lbl_sub)

        top_lay.addSpacing(24)

        nav_names = ["Dashboard", "Scan", "Analyze", "Logs", "Settings"]
        for idx, name in enumerate(nav_names):
            btn = QPushButton(name)
            btn.setObjectName("NavTabButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setProperty("active", "true" if idx == 0 else "false")
            btn.clicked.connect(lambda checked=False, i=idx: self.switch_page(i))
            top_lay.addWidget(btn)
            self._nav_buttons.append(btn)

        top_lay.addStretch()

        self.lbl_telemetry_badge = QLabel("Telemetry: Estimated / NIC Counters")
        self.lbl_telemetry_badge.setFixedHeight(28)
        self.lbl_telemetry_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_telemetry_badge.setStyleSheet(
            "background-color: #2A2111; color: #FBBF24; border: 1px solid #92400E; "
            "border-radius: 14px; padding: 4px 12px; font-size: 11px; font-weight: 700;"
        )
        self.lbl_telemetry_badge.setToolTip(
            "Indicates whether metrics come from live packet capture, OS NIC/socket counters (estimated), or simulated demo telemetry."
        )
        top_lay.addWidget(self.lbl_telemetry_badge)

        c_status = "C Engine: ACTIVE" if self.c_engine.is_native_loaded else "C Engine: Fallback"
        self.lbl_c_badge = QLabel(c_status)
        self.lbl_c_badge.setObjectName("EngineBadge")
        self.lbl_c_badge.setFixedHeight(28)
        self.lbl_c_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_c_badge.setToolTip(self.c_engine.version())
        top_lay.addWidget(self.lbl_c_badge)

        self.btn_bell = QPushButton("🔔 0")
        self.btn_bell.setToolTip("View Active Security Alerts")
        self.btn_bell.setStyleSheet(
            "background-color: #1A1E29; color: #F87171; border: 1px solid #333A4B; "
            "border-radius: 14px; padding: 4px 10px; font-weight: 800;"
        )
        self.btn_bell.clicked.connect(lambda: self.switch_page(3))
        top_lay.addWidget(self.btn_bell)

        self.btn_admin_menu = QPushButton("🛡 Admin")
        self.btn_admin_menu.setStyleSheet(
            "background-color: #1A1E29; color: #F8FAFC; border: 1px solid #333A4B; "
            "border-radius: 14px; padding: 4px 14px; font-weight: 700;"
        )
        admin_menu = QMenu(self)
        act_scan = QAction("Start Network Scan Now", self)
        act_scan.triggered.connect(self.start_network_scan)
        act_spoof = QAction("Simulate ARP Spoofing Attack (C Engine)", self)
        act_spoof.triggered.connect(self.simulate_arp_spoofing_attack)
        act_csv = QAction("Export Devices CSV Report...", self)
        act_csv.triggered.connect(lambda: self.export_csv_report())
        act_json = QAction("Export Full Audit JSON Report...", self)
        act_json.triggered.connect(lambda: self.export_json_report())
        admin_menu.addAction(act_scan)
        admin_menu.addAction(act_spoof)
        admin_menu.addSeparator()
        admin_menu.addAction(act_csv)
        admin_menu.addAction(act_json)
        self.btn_admin_menu.setMenu(admin_menu)
        top_lay.addWidget(self.btn_admin_menu)

        root_vbox.addWidget(top_bar)

        # =====================================================================
        # 2. BODY AREA (Left Icon Sidebar + Main Tab/Stacked Area)
        # =====================================================================
        body_widget = QWidget()
        body_hbox = QHBoxLayout(body_widget)
        body_hbox.setContentsMargins(0, 0, 0, 0)
        body_hbox.setSpacing(0)

        # Left Vertical Icon Sidebar (Photo 1)
        sidebar = QFrame()
        sidebar.setObjectName("LeftSidebar")
        sidebar.setFixedWidth(54)
        side_lay = QVBoxLayout(sidebar)
        side_lay.setContentsMargins(4, 14, 4, 14)
        side_lay.setSpacing(8)

        side_specs = [
            ("⌂", "Dashboard (Cyber Guardian Overview)", 0),
            ("⊞", "Scan (Live Network Devices & Port Inspector)", 1),
            ("◎", "Analyze (Traffic Overview & Flows Spiral)", 2),
            ("☰", "Logs (Security Alerts & History Timeline)", 3),
            ("⚙", "Settings (Interfaces, Auto-Scan & Diagnostics)", 4),
        ]
        for icon_txt, tooltip, page_idx in side_specs:
            sbtn = QPushButton(icon_txt)
            sbtn.setObjectName("SidebarIconBtn")
            sbtn.setToolTip(tooltip)
            sbtn.setCursor(Qt.CursorShape.PointingHandCursor)
            sbtn.setProperty("active", "true" if page_idx == 0 else "false")
            sbtn.clicked.connect(lambda checked=False, i=page_idx: self.switch_page(i))
            side_lay.addWidget(sbtn)
            self._side_buttons.append(sbtn)

        side_lay.addStretch()

        btn_sim_side = QPushButton("⚡")
        btn_sim_side.setObjectName("SidebarIconBtn")
        btn_sim_side.setToolTip("Simulate Gratuitous ARP Attack via Native C Engine")
        btn_sim_side.setStyleSheet("color: #F59E0B; font-size: 16px;")
        btn_sim_side.clicked.connect(self.simulate_arp_spoofing_attack)
        side_lay.addWidget(btn_sim_side)

        body_hbox.addWidget(sidebar)

        # Main TabWidget (TabBar hidden because TopNavBar + LeftSidebar control it)
        self.tabs = QTabWidget()
        self.tabs.tabBar().setVisible(False)
        self.tabs.currentChanged.connect(self._sync_nav_State)
        body_hbox.addWidget(self.tabs, stretch=1)

        root_vbox.addWidget(body_widget, stretch=1)

        # Build the 5 pages
        self._build_dashboard_page()  # Page 0: Photo 1 Cyber Guardian Dashboard
        self._build_scan_page()       # Page 1: Live Device Grid & Inspector
        self._build_analyze_page()    # Page 2: Photo 2 Traffic Overview & Flows Spiral
        self._build_logs_page()       # Page 3: Security Alerts Feed & Device History
        self._build_settings_page()   # Page 4: Settings, Interfaces & Diagnostics

        # Status Bar & Progress Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(220)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready. Click 'Start Scan' to discover active devices and analyze ports.")

    def switch_page(self, index: int) -> None:
        """Switch active page across TopNavBar, LeftSidebar, and QTabWidget."""
        if 0 <= index < self.tabs.count():
            self.tabs.setCurrentIndex(index)
            self._sync_nav_State(index)

    def _sync_nav_State(self, index: int) -> None:
        # Map index (if old test calls setCurrentIndex(1) expecting alerts, keep tabs accessible)
        for i, btn in enumerate(self._nav_buttons):
            btn.setProperty("active", "true" if i == index else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        for i, sbtn in enumerate(self._side_buttons):
            sbtn.setProperty("active", "true" if i == index else "false")
            sbtn.style().unpolish(sbtn)
            sbtn.style().polish(sbtn)

    # =========================================================================
    # PAGE 0: CYBER GUARDIAN DASHBOARD (PHOTO 1 EXACT LAYOUT)
    # =========================================================================
    def _build_dashboard_page(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(16, 12, 16, 10)
        lay.setSpacing(12)

        # --- Top KPI Status Strip (Photo 1) ---
        strip = QFrame()
        strip.setObjectName("StatusStripBar")
        strip.setFixedHeight(66)
        strip_lay = QHBoxLayout(strip)
        strip_lay.setContentsMargins(18, 8, 18, 8)
        strip_lay.setSpacing(16)

        # KPI 1: Network Status: ACTIVE
        cell1 = QFrame()
        cell1.setObjectName("KpiCell")
        c1_lay = QHBoxLayout(cell1)
        c1_lay.setContentsMargins(0, 0, 16, 0)
        c1_lay.setSpacing(12)
        lbl_sig = QLabel("((•))")
        lbl_sig.setFixedSize(38, 38)
        lbl_sig.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_sig.setStyleSheet(
            "background-color: #063E2E; color: #22C55E; border: 1px solid #059669; "
            "border-radius: 19px; font-weight: 900; font-size: 11px;"
        )
        c1_lay.addWidget(lbl_sig)
        c1_v = QVBoxLayout()
        c1_v.setSpacing(1)
        l1_t = QLabel("Network Status:")
        l1_t.setObjectName("KpiLabel")
        self.lbl_kpi_net_status = QLabel("ACTIVE")
        self.lbl_kpi_net_status.setObjectName("KpiValueActive")
        c1_v.addWidget(l1_t)
        c1_v.addWidget(self.lbl_kpi_net_status)
        c1_lay.addLayout(c1_v, stretch=1)
        strip_lay.addWidget(cell1, stretch=1)

        # KPI 2: Devices Scanned
        cell2 = QFrame()
        cell2.setObjectName("KpiCell")
        c2_lay = QHBoxLayout(cell2)
        c2_lay.setContentsMargins(0, 0, 16, 0)
        c2_lay.setSpacing(12)
        lbl_dev_ico = QLabel("▣")
        lbl_dev_ico.setFixedSize(38, 38)
        lbl_dev_ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_dev_ico.setStyleSheet(
            "background-color: #2A2111; color: #FBBF24; border: 1px solid #92400E; "
            "border-radius: 9px; font-size: 16px; font-weight: 800;"
        )
        c2_lay.addWidget(lbl_dev_ico)
        c2_v = QVBoxLayout()
        c2_v.setSpacing(1)
        l2_t = QLabel("Devices Scanned:")
        l2_t.setObjectName("KpiLabel")
        self.lbl_kpi_devices = QLabel("0")
        self.lbl_kpi_devices.setObjectName("KpiValueWhite")
        c2_v.addWidget(l2_t)
        c2_v.addWidget(self.lbl_kpi_devices)
        c2_lay.addLayout(c2_v, stretch=1)
        strip_lay.addWidget(cell2, stretch=1)

        # KPI 3: Open Ports
        cell3 = QFrame()
        cell3.setObjectName("KpiCell")
        c3_lay = QHBoxLayout(cell3)
        c3_lay.setContentsMargins(0, 0, 16, 0)
        c3_lay.setSpacing(12)
        lbl_port_ico = QLabel("◎")
        lbl_port_ico.setFixedSize(38, 38)
        lbl_port_ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_port_ico.setStyleSheet(
            "background-color: #2A2111; color: #FBBF24; border: 1px solid #92400E; "
            "border-radius: 19px; font-size: 16px; font-weight: 800;"
        )
        c3_lay.addWidget(lbl_port_ico)
        c3_v = QVBoxLayout()
        c3_v.setSpacing(1)
        l3_t = QLabel("Open Ports:")
        l3_t.setObjectName("KpiLabel")
        self.lbl_kpi_open_ports = QLabel("0")
        self.lbl_kpi_open_ports.setObjectName("KpiValueWhite")
        c3_v.addWidget(l3_t)
        c3_v.addWidget(self.lbl_kpi_open_ports)
        c3_lay.addLayout(c3_v, stretch=1)
        strip_lay.addWidget(cell3, stretch=1)

        # KPI 4: Threat Level + Start Scan Golden CTA Button
        cell4 = QFrame()
        c4_lay = QHBoxLayout(cell4)
        c4_lay.setContentsMargins(0, 0, 0, 0)
        c4_lay.setSpacing(12)
        lbl_warn_ico = QLabel("▲")
        lbl_warn_ico.setFixedSize(38, 38)
        lbl_warn_ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_warn_ico.setStyleSheet(
            "background-color: #2A2111; color: #F59E0B; border: 1px solid #B45309; "
            "border-radius: 9px; font-size: 15px; font-weight: 800;"
        )
        c4_lay.addWidget(lbl_warn_ico)
        c4_v = QVBoxLayout()
        c4_v.setSpacing(1)
        l4_t = QLabel("Threat Level:")
        l4_t.setObjectName("KpiLabel")
        self.lbl_kpi_threat = QLabel("ELEVATED (Amber)")
        self.lbl_kpi_threat.setObjectName("KpiValueElevated")
        c4_v.addWidget(l4_t)
        c4_v.addWidget(self.lbl_kpi_threat)
        c4_lay.addLayout(c4_v, stretch=1)

        self.btn_scan_now = QPushButton("Start Scan")
        self.btn_scan_now.setObjectName("GoldScanButton")
        self.btn_scan_now.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan_now.clicked.connect(self.start_network_scan)
        c4_lay.addWidget(self.btn_scan_now)

        strip_lay.addWidget(cell4, stretch=1)
        lay.addWidget(strip)

        # --- Middle Row: Port Overview Gauge | Real-Time Packet Flow | Top Protocols ---
        mid_row = QHBoxLayout()
        mid_row.setSpacing(12)

        # Card 1: Network Port Overview
        card_ports = QFrame()
        card_ports.setObjectName("CyberCard")
        cp_lay = QVBoxLayout(card_ports)
        cp_lay.setContentsMargins(14, 12, 14, 10)
        cp_lay.setSpacing(4)
        cp_hdr = QHBoxLayout()
        lbl_cp = QLabel("Network Port Overview")
        lbl_cp.setObjectName("CardHeaderTitle")
        cp_hdr.addWidget(lbl_cp)
        cp_hdr.addStretch()
        lbl_dots1 = QLabel("•••")
        lbl_dots1.setStyleSheet("color: #64748B; font-weight: bold;")
        cp_hdr.addWidget(lbl_dots1)
        cp_lay.addLayout(cp_hdr)

        self.port_gauge = PortOverviewGaugeWidget()
        cp_lay.addWidget(self.port_gauge, stretch=1)
        mid_row.addWidget(card_ports, stretch=3)

        # Card 2: Real-Time Packet Flow (Center wide card with golden bottom accent)
        card_flow = QFrame()
        card_flow.setObjectName("CyberCardGold")
        cf_lay = QVBoxLayout(card_flow)
        cf_lay.setContentsMargins(16, 12, 16, 10)
        cf_lay.setSpacing(4)
        cf_hdr = QHBoxLayout()
        self.lbl_packet_flow_title = QLabel("Packet Flow (NIC Counters / Estimated Telemetry)")
        self.lbl_packet_flow_title.setObjectName("CardHeaderTitle")
        cf_hdr.addWidget(self.lbl_packet_flow_title)
        cf_hdr.addStretch()
        self.combo_timeline_window = QComboBox()
        self.combo_timeline_window.addItems(["Live Timeline", "Last 15m", "Last 1h"])
        self.combo_timeline_window.setFixedWidth(135)
        self.combo_timeline_window.currentIndexChanged.connect(lambda _: self._update_telemetry_views())
        cf_hdr.addWidget(self.combo_timeline_window)
        cf_lay.addLayout(cf_hdr)

        self.packet_flow_chart = RealtimePacketFlowChart()
        cf_lay.addWidget(self.packet_flow_chart, stretch=1)
        mid_row.addWidget(card_flow, stretch=6)

        # Card 3: Top Protocols
        card_proto = QFrame()
        card_proto.setObjectName("CyberCard")
        cpr_lay = QVBoxLayout(card_proto)
        cpr_lay.setContentsMargins(14, 12, 14, 10)
        cpr_lay.setSpacing(4)
        cpr_hdr = QHBoxLayout()
        lbl_cpr = QLabel("Top Protocols")
        lbl_cpr.setObjectName("CardHeaderTitle")
        cpr_hdr.addWidget(lbl_cpr)
        cpr_hdr.addStretch()
        lbl_dots2 = QLabel("•••")
        lbl_dots2.setStyleSheet("color: #64748B; font-weight: bold;")
        cpr_hdr.addWidget(lbl_dots2)
        cpr_lay.addLayout(cpr_hdr)

        self.top_protocols_chart = TopProtocolsBarChart()
        cpr_lay.addWidget(self.top_protocols_chart, stretch=1)
        mid_row.addWidget(card_proto, stretch=3)

        lay.addLayout(mid_row, stretch=5)

        # --- Bottom Row: Recent Scan Activity | Active Alerts | Packet Traffic Statistics ---
        bot_row = QHBoxLayout()
        bot_row.setSpacing(12)

        # Bottom Left Card: Recent Scan Activity
        card_recent = QFrame()
        card_recent.setObjectName("CyberCard")
        cr_lay = QVBoxLayout(card_recent)
        cr_lay.setContentsMargins(14, 12, 14, 12)
        cr_lay.setSpacing(8)
        cr_hdr = QHBoxLayout()
        lbl_cr = QLabel("Recent Scan Activity")
        lbl_cr.setObjectName("CardHeaderTitle")
        cr_hdr.addWidget(lbl_cr)
        cr_hdr.addStretch()
        btn_view_all_devs = QPushButton("View All ›")
        btn_view_all_devs.setStyleSheet(
            "background: transparent; border: none; color: #FBBF24; font-size: 11px; padding: 2px 6px;"
        )
        btn_view_all_devs.clicked.connect(lambda: self.switch_page(1))
        cr_hdr.addWidget(btn_view_all_devs)
        cr_lay.addLayout(cr_hdr)

        self.recent_scan_table = QTableWidget(0, 3)
        self.recent_scan_table.setHorizontalHeaderLabels(["Host IP", "Services Found", "Status"])
        self.recent_scan_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.recent_scan_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.recent_scan_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.recent_scan_table.verticalHeader().setVisible(False)
        self.recent_scan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.recent_scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_scan_table.setShowGrid(False)
        self.recent_scan_table.itemDoubleClicked.connect(self._on_recent_scan_row_activated)
        cr_lay.addWidget(self.recent_scan_table, stretch=1)
        bot_row.addWidget(card_recent, stretch=3)

        # Bottom Center Card: Active Alerts (Photo 1)
        card_alerts = QFrame()
        card_alerts.setObjectName("CyberCard")
        ca_lay = QVBoxLayout(card_alerts)
        ca_lay.setContentsMargins(16, 12, 16, 12)
        ca_lay.setSpacing(8)

        ca_hdr = QHBoxLayout()
        lbl_ca = QLabel("Active Alerts")
        lbl_ca.setObjectName("CardHeaderTitle")
        ca_hdr.addWidget(lbl_ca)
        ca_hdr.addStretch()

        self.btn_dash_sim_spoof = QPushButton("⚡ Simulate Threat")
        self.btn_dash_sim_spoof.setObjectName("DangerButton")
        self.btn_dash_sim_spoof.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.btn_dash_sim_spoof.clicked.connect(self.simulate_arp_spoofing_attack)
        ca_hdr.addWidget(self.btn_dash_sim_spoof)

        self.combo_dash_alert_filter = QComboBox()
        self.combo_dash_alert_filter.addItems(["Filter Logs: All", "Critical Only", "Warning Only"])
        self.combo_dash_alert_filter.setFixedWidth(135)
        self.combo_dash_alert_filter.currentIndexChanged.connect(lambda _: self._populate_dashboard_alerts())
        ca_hdr.addWidget(self.combo_dash_alert_filter)
        ca_lay.addLayout(ca_hdr)

        # High Priority Banner
        hp_banner = QFrame()
        hp_banner.setObjectName("HighPriorityBanner")
        hp_banner.setFixedHeight(32)
        hp_lay = QHBoxLayout(hp_banner)
        hp_lay.setContentsMargins(12, 0, 12, 0)
        self.lbl_high_priority_count = QLabel("▲ High Priority: 0")
        self.lbl_high_priority_count.setStyleSheet("color: #F87171; font-weight: 800; font-size: 12px;")
        hp_lay.addWidget(self.lbl_high_priority_count)
        hp_lay.addStretch()
        btn_res_quick = QPushButton("Resolve All")
        btn_res_quick.setStyleSheet(
            "background: transparent; border: none; color: #94A3B8; font-size: 11px; font-weight: 600;"
        )
        btn_res_quick.clicked.connect(self.resolve_all_alerts)
        hp_lay.addWidget(btn_res_quick)
        ca_lay.addWidget(hp_banner)

        # Scrollable alert cards list
        self.dash_alerts_scroll = QScrollArea()
        self.dash_alerts_scroll.setWidgetResizable(True)
        self.dash_alerts_scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        self.dash_alerts_container = QWidget()
        self.dash_alerts_container.setStyleSheet("background: transparent;")
        self.dash_alerts_vbox = QVBoxLayout(self.dash_alerts_container)
        self.dash_alerts_vbox.setContentsMargins(0, 0, 4, 0)
        self.dash_alerts_vbox.setSpacing(6)
        self.dash_alerts_scroll.setWidget(self.dash_alerts_container)
        ca_lay.addWidget(self.dash_alerts_scroll, stretch=1)

        bot_row.addWidget(card_alerts, stretch=6)

        # Bottom Right Card: Packet Traffic Statistics (Photo 1)
        card_stats = QFrame()
        card_stats.setObjectName("CyberCard")
        cs_lay = QVBoxLayout(card_stats)
        cs_lay.setContentsMargins(16, 12, 16, 14)
        cs_lay.setSpacing(6)

        lbl_cs = QLabel("Packet Traffic Statistics")
        lbl_cs.setObjectName("CardHeaderTitle")
        cs_lay.addWidget(lbl_cs)

        self.lbl_telemetry_source_note = QLabel("Estimated Telemetry (NIC Counters — Live Pcap Inactive)")
        self.lbl_telemetry_source_note.setStyleSheet("color: #F59E0B; font-size: 10px; font-weight: 700;")
        self.lbl_telemetry_source_note.setWordWrap(True)
        cs_lay.addWidget(self.lbl_telemetry_source_note)

        lbl_tp_cap = QLabel("Total Packets")
        lbl_tp_cap.setObjectName("KpiLabel")
        cs_lay.addWidget(lbl_tp_cap)

        self.lbl_total_packets = QLabel("0")
        self.lbl_total_packets.setObjectName("StatHugeWhite")
        cs_lay.addWidget(self.lbl_total_packets)

        cs_lay.addSpacing(4)

        lbl_bps_cap = QLabel("Bits/Sec")
        lbl_bps_cap.setObjectName("KpiLabel")
        cs_lay.addWidget(lbl_bps_cap)

        self.lbl_bits_per_sec = QLabel("0.0Mbps")
        self.lbl_bits_per_sec.setObjectName("StatHugeGold")
        cs_lay.addWidget(self.lbl_bits_per_sec)

        cs_lay.addStretch()

        self.lbl_iface_mini = QLabel("")
        self.lbl_iface_mini.setStyleSheet("color: #64748B; font-size: 11px;")
        self.lbl_iface_mini.setWordWrap(True)
        cs_lay.addWidget(self.lbl_iface_mini)

        bot_row.addWidget(card_stats, stretch=3)
        lay.addLayout(bot_row, stretch=4)

        # --- Bottom Timeline Scrubber Bar (Photo 1) ---
        scrubber_bar = QHBoxLayout()
        scrubber_bar.setContentsMargins(4, 2, 4, 0)
        scrubber_bar.setSpacing(8)

        btn_prev_t = QPushButton("‹")
        btn_prev_t.setFixedSize(24, 22)
        btn_prev_t.setStyleSheet("padding: 0px; font-weight: bold;")
        btn_prev_t.clicked.connect(
            lambda: self.timeline_slider.setValue(max(20, self.timeline_slider.value() - 10))
        )
        btn_next_t = QPushButton("›")
        btn_next_t.setFixedSize(24, 22)
        btn_next_t.setStyleSheet("padding: 0px; font-weight: bold;")
        btn_next_t.clicked.connect(
            lambda: self.timeline_slider.setValue(min(100, self.timeline_slider.value() + 10))
        )
        scrubber_bar.addWidget(btn_prev_t)
        scrubber_bar.addWidget(btn_next_t)

        self.timeline_slider = TimelineScrubberSlider(Qt.Orientation.Horizontal)
        self.timeline_slider.setRange(20, 100)
        self.timeline_slider.setValue(100)
        self.timeline_slider.setToolTip("Scrub historical packet flow timeline")
        self.timeline_slider.valueChanged.connect(lambda _: self._update_telemetry_views())
        scrubber_bar.addWidget(self.timeline_slider, stretch=1)

        lbl_time_end = QLabel("Time")
        lbl_time_end.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 600;")
        scrubber_bar.addWidget(lbl_time_end)

        lay.addLayout(scrubber_bar)

        self.tabs.addTab(page, "Dashboard")

    # =========================================================================
    # PAGE 1: SCAN — LIVE DEVICE INVENTORY & PORT INSPECTOR
    # =========================================================================
    def _build_scan_page(self) -> None:
        devices_tab = QWidget()
        dev_layout = QVBoxLayout(devices_tab)
        dev_layout.setContentsMargins(16, 12, 16, 12)
        dev_layout.setSpacing(10)

        # KPI Summary Strip for Scan Tab
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        card_defs: List[Tuple[str, str, str]] = [
            ("total_devices", "TOTAL DEVICES", "#F8FAFC"),
            ("online_devices", "ONLINE NOW", "#10B981"),
            ("offline_devices", "OFFLINE", "#94A3B8"),
            ("trusted_devices", "TRUSTED", "#38BDF8"),
            ("high_risk_devices", "HIGH / CRITICAL RISK", "#F59E0B"),
            ("unresolved_alerts", "ACTIVE ALERTS", "#EF4444"),
        ]
        for key, title, color in card_defs:
            card = QFrame()
            card.setObjectName("StatCard")
            c_lay = QVBoxLayout(card)
            c_lay.setContentsMargins(14, 8, 14, 8)
            c_lay.setSpacing(2)

            lbl_t = QLabel(title)
            lbl_t.setObjectName("CardTitle")
            lbl_v = QLabel("0")
            lbl_v.setObjectName("CardValue")
            lbl_v.setStyleSheet(f"color: {color};")

            c_lay.addWidget(lbl_t)
            c_lay.addWidget(lbl_v)
            cards_layout.addWidget(card)
            self._stat_labels[key] = lbl_v

        dev_layout.addLayout(cards_layout)

        # Filter & Action Bar
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

        self.btn_scan_page_trigger = QPushButton("Start Scan")
        self.btn_scan_page_trigger.setObjectName("GoldScanButton")
        self.btn_scan_page_trigger.clicked.connect(self.start_network_scan)
        filter_row.addWidget(self.btn_scan_page_trigger)

        self.btn_inspect = QPushButton("Inspect Device & Ports")
        self.btn_inspect.clicked.connect(self.inspect_selected_device)
        filter_row.addWidget(self.btn_inspect)

        self.btn_toggle_trust = QPushButton("Toggle Trusted Status")
        self.btn_toggle_trust.setObjectName("SuccessButton")
        self.btn_toggle_trust.clicked.connect(self.toggle_selected_device_trust)
        filter_row.addWidget(self.btn_toggle_trust)

        self.btn_sim_spoof = QPushButton("Simulate ARP Attack")
        self.btn_sim_spoof.setObjectName("DangerButton")
        self.btn_sim_spoof.clicked.connect(self.simulate_arp_spoofing_attack)
        filter_row.addWidget(self.btn_sim_spoof)

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
        dev_layout.addWidget(self.devices_table, stretch=1)

        self.tabs.addTab(devices_tab, "Scan")

    # =========================================================================
    # PAGE 2: ANALYZE — TRAFFIC OVERVIEW & FLOWS SPIRAL (PHOTO 2 EXACT LAYOUT)
    # =========================================================================
    def _build_analyze_page(self) -> None:
        analyze_tab = QWidget()
        alay = QVBoxLayout(analyze_tab)
        alay.setContentsMargins(14, 8, 14, 8)
        alay.setSpacing(6)

        # --- Top NQL Query & Telemetry Control Bar (Photo 2) ---
        nql_bar = QFrame()
        nql_bar.setObjectName("TelemetryPanel")
        nql_lay = QHBoxLayout(nql_bar)
        nql_lay.setContentsMargins(10, 5, 10, 5)
        nql_lay.setSpacing(10)

        lbl_flow_pill = QLabel("Flow ▾")
        lbl_flow_pill.setStyleSheet(
            "background-color: #0284C7; color: #FFFFFF; border-radius: 11px; "
            "padding: 4px 12px; font-weight: 800; font-size: 11px;"
        )
        nql_lay.addWidget(lbl_flow_pill)

        self.nql_input = QLineEdit()
        self.nql_input.setPlaceholderText(
            "NQL  Example: srcport >= 80 AND dstport != 443 && proto == tcp"
        )
        self.nql_input.returnPressed.connect(self._update_telemetry_views)
        nql_lay.addWidget(self.nql_input, stretch=1)

        lbl_last4h = QLabel("Last 4 hours")
        lbl_last4h.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 600;")
        nql_lay.addWidget(lbl_last4h)

        self.btn_nql_refresh = QPushButton("REFRESH")
        self.btn_nql_refresh.setObjectName("CyanRefreshButton")
        self.btn_nql_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_nql_refresh.clicked.connect(self._update_telemetry_views)
        nql_lay.addWidget(self.btn_nql_refresh)

        alay.addWidget(nql_bar)

        # --- Sub-Header Bar: Display Labels | Metric | Traffic Overview | SYNC HOVER (Photo 2) ---
        sub_bar = QFrame()
        sub_bar.setObjectName("TelemetryPanel")
        sub_lay = QHBoxLayout(sub_bar)
        sub_lay.setContentsMargins(10, 4, 10, 4)
        sub_lay.setSpacing(12)

        lbl_view_sel = QLabel("Traffic Overview  ▾")
        lbl_view_sel.setStyleSheet(
            "background-color: #1A1E29; color: #E2E8F0; border: 1px solid #2E3444; "
            "border-radius: 5px; padding: 3px 10px; font-size: 11px; font-weight: 600;"
        )
        sub_lay.addWidget(lbl_view_sel)

        lbl_disp = QLabel("Display Labels:")
        lbl_disp.setStyleSheet("color: #94A3B8; font-size: 11px;")
        sub_lay.addWidget(lbl_disp)
        self.combo_display_labels = QComboBox()
        self.combo_display_labels.addItems(["name", "ip + port", "vendor"])
        self.combo_display_labels.setFixedWidth(96)
        sub_lay.addWidget(self.combo_display_labels)

        lbl_metric = QLabel("Metric:")
        lbl_metric.setStyleSheet("color: #94A3B8; font-size: 11px;")
        sub_lay.addWidget(lbl_metric)
        self.combo_analyze_metric = QComboBox()
        self.combo_analyze_metric.addItems(["bitrate", "packets", "flows"])
        self.combo_analyze_metric.setFixedWidth(96)
        self.combo_analyze_metric.currentIndexChanged.connect(lambda _: self._update_telemetry_views())
        sub_lay.addWidget(self.combo_analyze_metric)

        for ico_txt, tip_txt in [("🖨", "Export JSON Audit Snapshot"), ("🔗", "Copy NQL Filter")]:
            b_ico = QPushButton(ico_txt)
            b_ico.setFixedSize(24, 24)
            b_ico.setToolTip(tip_txt)
            b_ico.setStyleSheet(
                "background-color: #0284C7; color: #FFFFFF; border: none; "
                "border-radius: 12px; padding: 0px; font-size: 11px; font-weight: bold;"
            )
            if ico_txt == "🖨":
                b_ico.clicked.connect(lambda: self.export_json_report())
            else:
                b_ico.clicked.connect(self._update_telemetry_views)
            sub_lay.addWidget(b_ico)

        self.chk_sync_hover = QCheckBox("SYNC HOVER")
        self.chk_sync_hover.setChecked(True)
        self.chk_sync_hover.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 11px;")
        sub_lay.addWidget(self.chk_sync_hover)

        self.chk_demo_telemetry = QCheckBox("Demo / Simulated Telemetry")
        self.chk_demo_telemetry.setChecked(False)
        self.chk_demo_telemetry.setToolTip(
            "Enable synthetic demo traffic waveforms for UI preview. Leave unchecked for honest NIC/socket telemetry."
        )
        self.chk_demo_telemetry.setStyleSheet("color: #F59E0B; font-weight: 700; font-size: 11px;")
        self.chk_demo_telemetry.toggled.connect(self._on_demo_telemetry_toggled)
        sub_lay.addWidget(self.chk_demo_telemetry)

        sub_lay.addStretch()
        alay.addWidget(sub_bar)

        # --- Upper 3-Column Telemetry Grid (Left 3 Charts | Center Flows Spiral | Right 3 Charts) ---
        upper_grid = QHBoxLayout()
        upper_grid.setSpacing(8)

        # Left Column: Bitrate, Packets Rate, Flow Rate
        left_col = QVBoxLayout()
        left_col.setSpacing(6)
        self.chart_bitrate = TelemetryAreaChart(
            title="Bitrate",
            unit="Mbps",
            accent_color="#F59E0B",
            y_labels=["300 Mbps", "200 Mbps", "100 Mbps", "0 bps"],
        )
        self.chart_packets_rate = TelemetryAreaChart(
            title="Packets Rate",
            unit="kpps",
            accent_color="#EA580C",
            y_labels=["25 kpps", "12 kpps", "0 pps"],
        )
        self.chart_flow_rate = TelemetryAreaChart(
            title="Flow Rate",
            unit="fps",
            accent_color="#A855F7",
            y_labels=["500 fps", "250 fps", "0 fps"],
        )
        for ch in (self.chart_bitrate, self.chart_packets_rate, self.chart_flow_rate):
            f_wrap = QFrame()
            f_wrap.setObjectName("TelemetryPanel")
            fw_lay = QVBoxLayout(f_wrap)
            fw_lay.setContentsMargins(4, 4, 4, 4)
            fw_lay.addWidget(ch)
            left_col.addWidget(f_wrap, stretch=1)
            self._telemetry_charts.append(ch)

        upper_grid.addLayout(left_col, stretch=3)

        # Center Column: Flows Spiral (Photo 2)
        spiral_frame = QFrame()
        spiral_frame.setObjectName("TelemetryPanel")
        sp_lay = QVBoxLayout(spiral_frame)
        sp_lay.setContentsMargins(10, 6, 10, 6)
        sp_lay.setSpacing(2)
        lbl_sp_title = QLabel("▼  Flows Spiral")
        lbl_sp_title.setStyleSheet("color: #F1F5F9; font-weight: 700; font-size: 12px;")
        sp_lay.addWidget(lbl_sp_title)
        self.flows_spiral = FlowsSpiralWidget()
        sp_lay.addWidget(self.flows_spiral, stretch=1)
        upper_grid.addWidget(spiral_frame, stretch=4)

        # Right Column: Source IP Cardinality, Site, Source Country / Vendor
        right_col = QVBoxLayout()
        right_col.setSpacing(6)
        self.chart_ip_cardinality = TelemetryAreaChart(
            title="Source IP Cardinality",
            unit="IPs",
            accent_color="#8B5CF6",
            y_labels=["100", "50", "25", "0"],
        )
        self.chart_site_traffic = TelemetryAreaChart(
            title="Site",
            unit="Mbps",
            accent_color="#EAB308",
            y_labels=["300 Mbps", "200 Mbps", "100 Mbps", "0 bps"],
            legend_items=[("LAN-Primary", "#EAB308"), ("Gateway", "#EF4444")],
        )
        self.chart_vendor_traffic = TelemetryAreaChart(
            title="Source Country / Vendor",
            unit="Mbps",
            accent_color="#EF4444",
            y_labels=["300 Mbps", "200 Mbps", "100 Mbps", "0 bps"],
            legend_items=[
                ("LAN-Core", "#EF4444"),
                ("Gateway", "#22C55E"),
                ("Workstations", "#38BDF8"),
                ("IoT-Nodes", "#F59E0B"),
            ],
        )
        for ch in (self.chart_ip_cardinality, self.chart_site_traffic, self.chart_vendor_traffic):
            f_wrap = QFrame()
            f_wrap.setObjectName("TelemetryPanel")
            fw_lay = QVBoxLayout(f_wrap)
            fw_lay.setContentsMargins(4, 4, 4, 4)
            fw_lay.addWidget(ch)
            right_col.addWidget(f_wrap, stretch=1)
            self._telemetry_charts.append(ch)

        upper_grid.addLayout(right_col, stretch=3)
        alay.addLayout(upper_grid, stretch=5)

        # Wire synchronized hover across all 6 telemetry area charts
        for ch in self._telemetry_charts:
            ch.hovered_ratio_changed.connect(self._on_telemetry_hover_changed)

        # --- Middle Row: Protocol Breakdown & Port Breakdown (Photo 2) ---
        mid_break = QHBoxLayout()
        mid_break.setSpacing(8)

        proto_frame = QFrame()
        proto_frame.setObjectName("TelemetryPanel")
        pf_lay = QVBoxLayout(proto_frame)
        pf_lay.setContentsMargins(4, 4, 4, 4)
        self.proto_breakdown_bar = HorizontalBreakdownBarWidget("Protocol Breakdown")
        pf_lay.addWidget(self.proto_breakdown_bar)
        mid_break.addWidget(proto_frame, stretch=1)

        port_frame = QFrame()
        port_frame.setObjectName("TelemetryPanel")
        ptf_lay = QVBoxLayout(port_frame)
        ptf_lay.setContentsMargins(4, 4, 4, 4)
        self.port_breakdown_bar = HorizontalBreakdownBarWidget("Port Breakdown")
        ptf_lay.addWidget(self.port_breakdown_bar)
        mid_break.addWidget(port_frame, stretch=1)

        alay.addLayout(mid_break, stretch=2)

        # --- Bottom Full-Width Panel: TCP Flag Distribution (Photo 2) ---
        tcp_frame = QFrame()
        tcp_frame.setObjectName("TelemetryPanel")
        tf_lay = QVBoxLayout(tcp_frame)
        tf_lay.setContentsMargins(4, 4, 4, 4)
        self.tcp_flag_widget = TcpFlagDistributionWidget()
        tf_lay.addWidget(self.tcp_flag_widget)
        alay.addWidget(tcp_frame, stretch=3)

        self.tabs.addTab(analyze_tab, "Analyze")

    def _on_telemetry_hover_changed(self, ratio: Optional[float]) -> None:
        if not self.chk_sync_hover.isChecked():
            return
        for ch in self._telemetry_charts:
            ch.set_hover_ratio(ratio)

    def _on_demo_telemetry_toggled(self, checked: bool) -> None:
        self.traffic_monitor.set_demo_mode(checked)
        self._update_telemetry_views()

    # =========================================================================
    # PAGE 3: LOGS — SECURITY ALERTS FEED & DEVICE STATE HISTORY
    # =========================================================================
    def _build_logs_page(self) -> None:
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.setContentsMargins(16, 12, 16, 12)
        logs_layout.setSpacing(10)

        alert_actions = QHBoxLayout()
        lbl_sec_hdr = QLabel("Security Intrusion & Anomaly Alerts")
        lbl_sec_hdr.setObjectName("CardHeaderTitle")
        alert_actions.addWidget(lbl_sec_hdr)
        alert_actions.addSpacing(16)

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

        logs_layout.addLayout(alert_actions)

        self.alerts_table = QTableWidget(0, 7)
        self.alerts_table.setHorizontalHeaderLabels(
            ["ID", "Timestamp", "Severity", "Alert Type", "IP Address", "MAC Address", "Description"]
        )
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.alerts_table.setAlternatingRowColors(True)
        logs_layout.addWidget(self.alerts_table, stretch=3)

        lbl_hist_hdr = QLabel("Device State History Timeline (First Seen / IP Changes / Reconnections)")
        lbl_hist_hdr.setObjectName("CardHeaderTitle")
        logs_layout.addWidget(lbl_hist_hdr)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(
            ["Timestamp", "Event Type", "MAC Address", "IP Address", "Details"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.setAlternatingRowColors(True)
        logs_layout.addWidget(self.history_table, stretch=2)

        self.tabs.addTab(logs_tab, "Logs")

    # =========================================================================
    # PAGE 4: SETTINGS — INTERFACES, AUTO-SCAN, EXPORT & ENGINE DIAGNOSTICS
    # =========================================================================
    def _build_settings_page(self) -> None:
        settings_tab = QWidget()
        slay = QVBoxLayout(settings_tab)
        slay.setContentsMargins(20, 16, 20, 16)
        slay.setSpacing(14)

        card_cfg = QFrame()
        card_cfg.setObjectName("CyberCard")
        form = QFormLayout(card_cfg)
        form.setContentsMargins(20, 18, 20, 18)
        form.setSpacing(12)

        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(340)
        for iface in self.interfaces:
            gw_str = f" | GW: {iface.gateway_ip}" if iface.gateway_ip else ""
            self.combo_iface.addItem(f"{iface.name} ({iface.cidr}{gw_str})")
        self.combo_iface.currentIndexChanged.connect(self._on_interface_changed)
        form.addRow("Active Network Interface:", self.combo_iface)

        auto_row = QHBoxLayout()
        self.chk_auto_scan = QCheckBox("Enable Periodic Background Discovery Scan")
        self.chk_auto_scan.setChecked(False)
        self.chk_auto_scan.toggled.connect(self._on_auto_scan_toggled)
        auto_row.addWidget(self.chk_auto_scan)

        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(10, 600)
        self.spin_interval.setSuffix(" sec")
        self.spin_interval.setValue(int(self.cfg.get("network", "scan_interval_seconds", 30)))
        self.spin_interval.valueChanged.connect(self._on_interval_changed)
        auto_row.addWidget(self.spin_interval)
        auto_row.addStretch()
        form.addRow("Auto-Scan Schedule:", auto_row)

        form.addRow(
            "Native C Packet Engine:",
            QLabel(
                f"{'ACTIVE' if self.c_engine.is_native_loaded else 'Python Fallback'} "
                f"— {self.c_engine.version()}"
            ),
        )
        health = self.db.check_health()
        form.addRow(
            "SQLite Database Status:",
            QLabel(f"{health['db_path']} (Journal: {health['journal_mode'].upper()})"),
        )

        exp_row = QHBoxLayout()
        self.btn_export_csv = QPushButton("Export Devices CSV Report")
        self.btn_export_csv.clicked.connect(lambda: self.export_csv_report())
        exp_row.addWidget(self.btn_export_csv)

        self.btn_export_json = QPushButton("Export Full Security Audit JSON")
        self.btn_export_json.clicked.connect(lambda: self.export_json_report())
        exp_row.addWidget(self.btn_export_json)
        exp_row.addStretch()
        form.addRow("Audit Reports:", exp_row)

        slay.addWidget(card_cfg)
        slay.addStretch()

        self.tabs.addTab(settings_tab, "Settings")

    # =========================================================================
    # SYSTEM TRAY, TIMERS & LIVE TELEMETRY UPDATES
    # =========================================================================
    def _setup_tray_icon(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = create_cyber_guardian_icon(32)
        self.tray_icon = QSystemTrayIcon(icon, self)
        self.tray_icon.setToolTip("Cyber Guardian — Network Port Scanner & Packet Analyzer")

        tray_menu = QMenu(self)
        act_show = QAction("Show Cyber Guardian", self)
        act_show.triggered.connect(self.showNormal)
        act_scan = QAction("Start Network Scan Now", self)
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

        # Real-time 1.5s telemetry & chart refresh timer
        self.telemetry_timer = QTimer(self)
        self.telemetry_timer.timeout.connect(self._on_telemetry_tick)
        self.telemetry_timer.start(1500)

    def _on_telemetry_tick(self) -> None:
        iface_name = self.active_interface.name if self.active_interface else None
        slider_pos = self.timeline_slider.value() / 100.0
        nql = self.nql_input.text().strip()
        win_mode = self.combo_timeline_window.currentText()
        metric_mode = self.combo_analyze_metric.currentText()
        snap = self.traffic_monitor.record_tick(
            db=self.db,
            interface_name=iface_name,
            timeline_position=slider_pos,
            nql_query=nql,
            window_mode=win_mode,
            metric_mode=metric_mode,
        )
        self._apply_telemetry_snapshot(snap)

    def _update_telemetry_views(self) -> None:
        slider_pos = self.timeline_slider.value() / 100.0
        nql = self.nql_input.text().strip()
        win_mode = self.combo_timeline_window.currentText()
        metric_mode = self.combo_analyze_metric.currentText()
        snap = self.traffic_monitor.build_snapshot(
            db=self.db,
            timeline_position=slider_pos,
            nql_query=nql,
            window_mode=win_mode,
            metric_mode=metric_mode,
        )
        self._apply_telemetry_snapshot(snap)

    def _apply_telemetry_snapshot(self, snap: TelemetrySnapshot) -> None:
        # Update Dashboard (Photo 1) charts & statistics
        self.port_gauge.set_counts(snap.open_ports, snap.closed_ports, snap.filtered_ports)
        self.lbl_kpi_open_ports.setText(f"{snap.open_ports:,}")
        self.packet_flow_chart.set_samples(snap.samples)
        self.top_protocols_chart.set_protocols(snap.top_protocols)
        self.lbl_total_packets.setText(snap.total_packets_formatted)
        self.lbl_bits_per_sec.setText(snap.bits_per_sec_formatted)

        # Explicitly disclose whether telemetry is Live Capture, Estimated (NIC Counters), or Demo
        self.lbl_telemetry_source_note.setText(snap.telemetry_label)
        if "DEMO" in snap.telemetry_mode.upper():
            self.lbl_packet_flow_title.setText("Packet Flow (Demo / Simulated Telemetry)")
            self.lbl_telemetry_badge.setText("Telemetry: Demo / Simulated")
        elif snap.is_estimated:
            self.lbl_packet_flow_title.setText("Packet Flow (NIC Counters / Estimated Telemetry)")
            self.lbl_telemetry_badge.setText("Telemetry: Estimated / NIC Counters")
        else:
            self.lbl_packet_flow_title.setText("Real-Time Packet Flow (Live Packet Capture)")
            self.lbl_telemetry_badge.setText("Telemetry: Live Packet Capture")

        if self.active_interface:
            gw = self.active_interface.gateway_ip or "N/A"
            self.lbl_iface_mini.setText(
                f"NIC: {self.active_interface.name} ({self.active_interface.cidr})\nGateway: {gw}"
            )

        # Update Analyze / Traffic Overview (Photo 2) charts
        if snap.samples:
            ts_list = [s.timestamp for s in snap.samples]
            latest = snap.samples[-1]

            self.chart_bitrate.set_series(
                values=[s.bitrate_mbps for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[("bitrate", f"{latest.bitrate_mbps:.2f} Mbps", "#F59E0B")],
            )
            self.chart_packets_rate.set_series(
                values=[s.packets_per_sec / 1000.0 for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[("rate", f"{latest.packets_per_sec / 1000.0:.2f} kpps", "#EA580C")],
            )
            self.chart_flow_rate.set_series(
                values=[s.flow_rate_fps for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[("flowrate", f"{latest.flow_rate_fps:.1f} fps", "#A855F7")],
            )
            self.chart_ip_cardinality.set_series(
                values=[float(s.unique_ips) for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[("unique", str(latest.unique_ips), "#8B5CF6")],
            )
            self.chart_site_traffic.set_series(
                values=[s.site_mbps for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[
                    ("LAN-Primary", f"{latest.site_mbps:.1f} Mbps", "#EAB308"),
                    ("Gateway", f"{latest.gateway_mbps:.1f} Mbps", "#EF4444"),
                ],
                secondary_values=[s.gateway_mbps for s in snap.samples],
            )
            vb = latest.vendor_breakdown
            self.chart_vendor_traffic.set_series(
                values=[s.bitrate_mbps * 0.85 for s in snap.samples],
                timestamps=ts_list,
                callout_title=latest.full_timestamp[:16],
                callout_rows=[
                    ("LAN-Core", f"{vb.get('LAN-Core', 0.0):.1f} Mbps", "#EF4444"),
                    ("Gateway", f"{vb.get('Gateway', 0.0):.1f} Mbps", "#22C55E"),
                    ("Workstations", f"{vb.get('Workstations', 0.0):.1f} Mbps", "#38BDF8"),
                    ("IoT-Nodes", f"{vb.get('IoT-Nodes', 0.0):.1f} Mbps", "#F59E0B"),
                ],
                secondary_values=[s.bitrate_mbps * 0.45 for s in snap.samples],
            )

        self.flows_spiral.set_intensities(snap.spiral_intensities)
        self.proto_breakdown_bar.set_segments(snap.protocol_breakdown)
        self.port_breakdown_bar.set_segments(snap.port_breakdown)
        self.tcp_flag_widget.set_samples(snap.samples)

    # =========================================================================
    # SCANNING, SPOOFING SIMULATION & VIEW REFRESH
    # =========================================================================
    def _on_interface_changed(self, index: int) -> None:
        if 0 <= index < len(self.interfaces):
            self.active_interface = self.interfaces[index]
            self.spoof_detector.reset_baseline()
            self.status_bar.showMessage(
                f"Switched active interface to {self.active_interface.name} ({self.active_interface.cidr})"
            )
            self._update_telemetry_views()

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
        self.btn_scan_now.setText("Scanning...")
        self.btn_scan_page_trigger.setEnabled(False)
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
        self.btn_scan_now.setText("Start Scan")
        self.btn_scan_page_trigger.setEnabled(True)
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
        self.btn_scan_now.setText("Start Scan")
        self.btn_scan_page_trigger.setEnabled(True)
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
        self.traffic_monitor.ingest_raw_packet(raw_frame)
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
        self.status_bar.showMessage(
            f"CRITICAL ALERT: Native C Engine parsed spoofed ARP reply from {parsed.src_mac} claiming Gateway {gw_ip}!"
        )

    def refresh_all_views(self) -> None:
        """Refresh dashboard KPIs, telemetry charts, recent activity, alerts, devices, and history."""
        stats = self.db.get_dashboard_stats()
        for key, lbl in self._stat_labels.items():
            lbl.setText(str(stats.get(key, 0)))

        total_devs = stats.get("total_devices", 0)
        unresolved = stats.get("unresolved_alerts", 0)
        high_risk = stats.get("high_risk_devices", 0)

        self.lbl_kpi_devices.setText(f"{total_devs:,}")
        self.btn_bell.setText(f"🔔 {unresolved}")

        if high_risk > 0 or unresolved >= 2:
            self.lbl_kpi_threat.setText("CRITICAL (Red)" if high_risk > 0 else "ELEVATED (Amber)")
            self.lbl_kpi_threat.setStyleSheet(
                f"color: {'#EF4444' if high_risk > 0 else '#F59E0B'}; font-size: 16px; font-weight: 800;"
            )
        elif unresolved == 1:
            self.lbl_kpi_threat.setText("ELEVATED (Amber)")
            self.lbl_kpi_threat.setStyleSheet("color: #F59E0B; font-size: 16px; font-weight: 800;")
        else:
            self.lbl_kpi_threat.setText("ELEVATED (Amber)" if total_devs == 0 else "LOW (Secure)")
            self.lbl_kpi_threat.setStyleSheet(
                f"color: {'#F59E0B' if total_devs == 0 else '#22C55E'}; font-size: 16px; font-weight: 800;"
            )

        self.refresh_devices_table()
        self.refresh_alerts_table()
        self.refresh_history_table()
        self._populate_recent_scan_activity()
        self._populate_dashboard_alerts()
        self._update_telemetry_views()

    def _populate_recent_scan_activity(self) -> None:
        """Populate the 'Recent Scan Activity' card on the Dashboard (Photo 1 bottom-left)."""
        devices = self.db.get_all_devices(online_only=False)[:8]
        self.recent_scan_table.setRowCount(len(devices))

        for row_idx, dev in enumerate(devices):
            ports = self.db.get_device_ports(dev.mac)
            if ports:
                svc_names = ", ".join(p.service.upper()[:8] for p in ports[:3])
            else:
                svc_names = "ARP, ICMP" if dev.is_online else "—"

            ip_item = QTableWidgetItem(dev.ip)
            ip_item.setData(Qt.ItemDataRole.UserRole, dev.mac)
            ip_item.setForeground(QColor("#F8FAFC"))
            ip_item.setFont(QFont("Segoe UI", 9, QFont.Weight.DemiBold))
            self.recent_scan_table.setItem(row_idx, 0, ip_item)

            svc_item = QTableWidgetItem(svc_names)
            svc_item.setForeground(QColor("#CBD5E1"))
            self.recent_scan_table.setItem(row_idx, 1, svc_item)

            if dev.risk_level in ("CRITICAL", "HIGH"):
                status_txt = "CRIT" if dev.risk_level == "CRITICAL" else "WARN"
                status_col = "#EF4444" if dev.risk_level == "CRITICAL" else "#F59E0B"
            elif not dev.is_trusted:
                status_txt = "WARN"
                status_col = "#F59E0B"
            else:
                status_txt = "OK"
                status_col = "#22C55E"

            st_item = QTableWidgetItem(status_txt)
            st_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            st_item.setForeground(QColor(status_col))
            st_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.recent_scan_table.setItem(row_idx, 2, st_item)

    def _on_recent_scan_row_activated(self, item: QTableWidgetItem) -> None:
        row = item.row()
        ip_item = self.recent_scan_table.item(row, 0)
        if not ip_item:
            return
        mac = ip_item.data(Qt.ItemDataRole.UserRole)
        if not mac:
            return
        dev = self.db.get_device_by_mac(str(mac))
        if dev:
            dlg = DeviceDetailDialog(device=dev, db=self.db, parent=self)
            dlg.device_updated.connect(lambda _: self.refresh_all_views())
            dlg.exec()
            self.refresh_all_views()

    def _populate_dashboard_alerts(self) -> None:
        """Populate the 'Active Alerts' card on the Dashboard (Photo 1 bottom-center)."""
        while self.dash_alerts_vbox.count():
            child = self.dash_alerts_vbox.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        alerts = self.db.get_alerts(limit=25, unresolved_only=True)
        f_mode = self.combo_dash_alert_filter.currentText()
        if "Critical" in f_mode:
            alerts = [a for a in alerts if a.severity == "CRITICAL"]
        elif "Warning" in f_mode:
            alerts = [a for a in alerts if a.severity == "WARNING"]

        high_count = sum(1 for a in alerts if a.severity in ("CRITICAL", "WARNING"))
        self.lbl_high_priority_count.setText(f"▲ High Priority: {high_count}")

        if not alerts:
            empty_card = QFrame()
            empty_card.setObjectName("AlertItemCard")
            el = QHBoxLayout(empty_card)
            el.setContentsMargins(12, 10, 12, 10)
            lbl_ok = QLabel("✔  No active unresolved security alerts. Click '⚡ Simulate Threat' to test.")
            lbl_ok.setStyleSheet("color: #10B981; font-weight: 600; font-size: 12px;")
            el.addWidget(lbl_ok)
            self.dash_alerts_vbox.addWidget(empty_card)
            self.dash_alerts_vbox.addStretch()
            return

        for alert in alerts[:6]:
            item_card = QFrame()
            item_card.setObjectName("AlertItemCard")
            ilay = QHBoxLayout(item_card)
            ilay.setContentsMargins(12, 8, 12, 8)
            ilay.setSpacing(10)

            is_crit = alert.severity == "CRITICAL"
            badge = QLabel("!")
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setFixedSize(24, 24)
            badge.setStyleSheet(
                f"background-color: {'#3B1219' if is_crit else '#3B280B'}; "
                f"color: {'#F87171' if is_crit else '#FBBF24'}; "
                f"border: 1px solid {'#EF4444' if is_crit else '#F59E0B'}; "
                "border-radius: 12px; font-weight: 900; font-size: 12px;"
            )
            ilay.addWidget(badge)

            txt_v = QVBoxLayout()
            txt_v.setSpacing(2)
            friendly_title = alert.alert_type.replace("_", " ").title()
            if alert.alert_type == "ARP_SPOOFING":
                friendly_title = f"ARP Spoofing / MITM from {alert.ip}"
            elif alert.alert_type == "SUSPICIOUS_PORT":
                friendly_title = f"High-Risk Port Exposed on {alert.ip}"
            elif alert.alert_type == "NEW_DEVICE":
                friendly_title = f"New Untrusted Host Detected ({alert.ip})"

            lbl_t = QLabel(friendly_title)
            lbl_t.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 12px;")
            lbl_d = QLabel(alert.description)
            lbl_d.setStyleSheet("color: #94A3B8; font-size: 11px;")
            lbl_d.setWordWrap(True)
            txt_v.addWidget(lbl_t)
            txt_v.addWidget(lbl_d)
            ilay.addLayout(txt_v, stretch=1)

            btn_go = QPushButton("›")
            btn_go.setFixedSize(24, 24)
            btn_go.setToolTip("Inspect Alert in Logs")
            btn_go.setStyleSheet(
                "background: transparent; border: none; color: #94A3B8; font-size: 16px; font-weight: bold;"
            )
            btn_go.clicked.connect(lambda checked=False: self.switch_page(3))
            ilay.addWidget(btn_go)

            self.dash_alerts_vbox.addWidget(item_card)

        self.dash_alerts_vbox.addStretch()

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
            status_text = "● ONLINE" if dev.is_online else "○ OFFLINE"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor("#10B981" if dev.is_online else "#64748B"))
            status_item.setData(Qt.ItemDataRole.UserRole, dev.mac)
            self.devices_table.setItem(row_idx, 0, status_item)

            self.devices_table.setItem(row_idx, 1, QTableWidgetItem(dev.ip))

            mac_item = QTableWidgetItem(dev.mac)
            mac_item.setForeground(QColor("#FBBF24"))
            self.devices_table.setItem(row_idx, 2, mac_item)

            self.devices_table.setItem(row_idx, 3, QTableWidgetItem(dev.vendor))
            self.devices_table.setItem(row_idx, 4, QTableWidgetItem(dev.hostname))

            trust_text = "Trusted" if dev.is_trusted else "Untrusted"
            trust_item = QTableWidgetItem(trust_text)
            trust_item.setForeground(QColor("#22C55E" if dev.is_trusted else "#F59E0B"))
            self.devices_table.setItem(row_idx, 5, trust_item)

            risk_text = f"{dev.risk_level} ({dev.risk_score})"
            risk_item = QTableWidgetItem(risk_text)
            risk_color = RISK_COLORS.get(dev.risk_level, "#10B981")
            risk_item.setForeground(QColor(risk_color))
            self.devices_table.setItem(row_idx, 6, risk_item)

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
        if hasattr(self, "telemetry_timer"):
            self.telemetry_timer.stop()
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
        self.status_bar.showMessage(f"Exported full audit report to {out}")
        return out
