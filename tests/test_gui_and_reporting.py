"""Unit and headless GUI integration tests for Phase 5: PySide6 Desktop App, Notifications & Reporting."""

import csv
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, PortScanRecord, SecurityAlertRecord
from src.gui.main_window import MainWindow
from src.gui.views.device_detail_dialog import DeviceDetailDialog
from src.utils.config import ConfigManager
from src.utils.notifier import SystemNotifier
from src.utils.reporter import ReportExporter


def _get_qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


def test_csv_and_json_report_exporter(tmp_path: Path) -> None:
    """Verify CSV and JSON report generation and schema integrity."""
    db = DatabaseManager(db_path=tmp_path / "report_test.db")
    dev1 = DeviceRecord(
        mac="00:03:93:11:22:33",
        ip="192.168.1.20",
        hostname="macbook-pro",
        vendor="Apple, Inc.",
        is_online=True,
        is_trusted=True,
        risk_level="LOW",
        risk_score=5,
    )
    db.upsert_device(dev1)
    db.save_port_scan(
        PortScanRecord(mac=dev1.mac, ip=dev1.ip, port=22, service="ssh", banner="OpenSSH_9.0")
    )
    alert = SecurityAlertRecord(
        alert_type="NEW_DEVICE",
        severity="WARNING",
        mac=dev1.mac,
        ip=dev1.ip,
        description="Test alert",
    )
    db.record_alert(alert)

    csv_path = ReportExporter.export_devices_csv(db.get_all_devices(), tmp_path / "devices.csv")
    assert csv_path.exists()
    with csv_path.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["mac"] == "00:03:93:11:22:33"
    assert rows[0]["vendor"] == "Apple, Inc."

    alerts_csv = ReportExporter.export_alerts_csv(db.get_alerts(), tmp_path / "alerts.csv")
    assert alerts_csv.exists()

    json_path = ReportExporter.export_full_report_json(db, tmp_path / "audit.json")
    assert json_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary_statistics"]["total_devices"] == 1
    assert len(payload["devices"]) == 1
    assert payload["devices"][0]["open_ports"][0]["port"] == 22
    assert len(payload["security_alerts"]) == 1


def test_system_notifier_history() -> None:
    """Verify notification formatting and history recording."""
    notifier = SystemNotifier(enabled=False)
    alert = SecurityAlertRecord(
        alert_type="ARP_SPOOFING",
        severity="CRITICAL",
        mac="DE:AD:BE:EF:00:01",
        ip="192.168.1.1",
        description="Gateway MAC spoofed!",
    )
    ev = notifier.notify_alert(alert)
    assert "ARP Spoofing" in ev.title
    assert ev.severity == "CRITICAL"
    assert len(notifier.history) == 1


def test_main_window_table_filtering_trust_and_arp_attack_simulation(tmp_path: Path) -> None:
    """Verify PySide6 MainWindow rendering, search/filter, trust toggle, and C-engine ARP attack simulation."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_test.db")
    cfg = ConfigManager(tmp_path / "config.json")

    db.upsert_device(
        DeviceRecord(
            mac="50:C7:BF:00:00:01",
            ip="192.168.1.1",
            hostname="router",
            vendor="TP-Link Technologies Co., Ltd.",
            is_online=True,
            is_trusted=True,
            risk_level="LOW",
            risk_score=0,
        )
    )
    db.upsert_device(
        DeviceRecord(
            mac="24:0A:C4:AA:BB:CC",
            ip="192.168.1.55",
            hostname="esp32-cam",
            vendor="Espressif Inc.",
            is_online=True,
            is_trusted=False,
            risk_level="MEDIUM",
            risk_score=35,
        )
    )

    win = MainWindow(config=cfg, db=db)
    assert win.devices_table.rowCount() == 2

    # Search filter test
    win.search_input.setText("espressif")
    assert win.devices_table.rowCount() == 1
    win.search_input.setText("")
    assert win.devices_table.rowCount() == 2

    # Dropdown filter test: Untrusted Only
    win.combo_filter.setCurrentText("Untrusted Only")
    assert win.devices_table.rowCount() == 1
    win.combo_filter.setCurrentText("All Devices")
    assert win.devices_table.rowCount() == 2

    # Select row 0 and toggle trusted status
    win.devices_table.selectRow(0)
    dev_before = win._get_selected_device()
    assert dev_before is not None
    win.toggle_selected_device_trust()
    dev_after = db.get_device_by_mac(dev_before.mac)
    assert dev_after is not None
    assert dev_after.is_trusted != dev_before.is_trusted

    # Trigger Simulated ARP Spoofing Attack via Native C Engine
    win.simulate_arp_spoofing_attack()
    alerts = db.get_alerts(unresolved_only=True)
    assert any("ARP_SPOOFING" in a.alert_type and a.severity == "CRITICAL" for a in alerts)
    assert any("[SIMULATED]" in a.alert_type and "[SIMULATED]" in a.description for a in alerts)
    attacker = db.get_device_by_mac("DE:AD:BE:EF:CA:FE")
    assert attacker is not None
    assert attacker.risk_level == "CRITICAL"

    # Export CSV & JSON via MainWindow
    csv_out = win.export_csv_report(tmp_path / "gui_export.csv")
    json_out = win.export_json_report(tmp_path / "gui_export.json")
    assert csv_out is not None and csv_out.exists()
    assert json_out is not None and json_out.exists()

    # Resolve all alerts and verify risk score recalculation
    win.resolve_all_alerts()
    assert len(db.get_alerts(unresolved_only=True)) == 0
    attacker_after_resolve = db.get_device_by_mac("DE:AD:BE:EF:CA:FE")
    assert attacker_after_resolve is not None
    assert attacker_after_resolve.risk_level == "MEDIUM"
    assert db.get_dashboard_stats()["high_risk_devices"] == 0
    win.close()


def test_device_detail_dialog_save_and_ports_display(tmp_path: Path) -> None:
    """Verify DeviceDetailDialog loads ports/history and saves custom notes/trust."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "detail_dlg.db")
    dev = DeviceRecord(
        mac="B8:27:EB:11:22:33",
        ip="192.168.1.77",
        hostname="raspi-node",
        vendor="Raspberry Pi Foundation",
        is_trusted=False,
    )
    db.upsert_device(dev)
    db.save_port_scan(PortScanRecord(mac=dev.mac, ip=dev.ip, port=80, service="http", banner="nginx"))

    dlg = DeviceDetailDialog(device=dev, db=db)
    assert dlg.ports_table.rowCount() == 1
    assert dlg.history_table.rowCount() >= 1

    dlg.edit_hostname.setText("raspi-cluster-01")
    dlg.edit_notes.setText("Lab Kubernetes Node")
    dlg.chk_trusted.setChecked(True)
    dlg._on_save_changes()

    updated = db.get_device_by_mac(dev.mac)
    assert updated is not None
    assert updated.hostname == "raspi-cluster-01"
    assert updated.notes == "Lab Kubernetes Node"
    assert updated.is_trusted is True
    dlg.close()


def test_cyber_guardian_dashboard_and_traffic_overview_widgets(tmp_path: Path) -> None:
    """Verify Photo 1 (Cyber Guardian Dashboard) & Photo 2 (Traffic Overview) custom charts, NQL, and navigation."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "cyber_ui.db")
    cfg = ConfigManager(tmp_path / "config.json")

    dev = DeviceRecord(
        mac="00:1A:2B:3C:4D:5E",
        ip="192.168.1.10",
        hostname="core-switch",
        vendor="Cisco Systems",
        is_online=True,
        is_trusted=True,
    )
    db.upsert_device(dev)
    db.save_port_scan(PortScanRecord(mac=dev.mac, ip=dev.ip, port=22, service="ssh", banner="OpenSSH"))
    db.save_port_scan(PortScanRecord(mac=dev.mac, ip=dev.ip, port=443, service="https", banner="TLS"))

    win = MainWindow(config=cfg, db=db)
    win.show()

    # Verify all 5 top navigation pages exist and render cleanly
    assert win.tabs.count() == 5
    for page_idx in range(5):
        win.switch_page(page_idx)
        assert win.tabs.currentIndex() == page_idx
        pix = win.grab()
        assert not pix.isNull()

    # Verify Photo 1 Dashboard widgets reflect database state
    win.switch_page(0)
    assert win.port_gauge.open_ports == 2
    table_item = win.recent_scan_table.item(0, 1)
    assert table_item is not None and "SSH" in table_item.text()

    # Test timeline slider scrubbing & timeline window dropdown modes
    win.timeline_slider.setValue(50)
    assert len(win.packet_flow_chart._samples) >= 8
    win.timeline_slider.setValue(100)

    win.combo_timeline_window.setCurrentText("Last 15m")
    assert len(win.packet_flow_chart._samples) == 12
    win.combo_timeline_window.setCurrentText("Live Timeline")
    assert len(win.packet_flow_chart._samples) >= 24

    # Verify Top Protocols always sum to 100%
    assert sum(pct for _, pct in win.top_protocols_chart._protocols) == 100

    # Test Photo 2 Analyze page NQL filtering (including compound boolean & relational operators)
    win.switch_page(2)
    win.nql_input.setText("proto == udp")
    win._update_telemetry_views()
    assert win.proto_breakdown_bar._segments[1][0] == "udp"
    assert win.proto_breakdown_bar._segments[1][1] == 60.0
    assert sum(pct for _, pct in win.top_protocols_chart._protocols) == 100

    win.nql_input.setText("port == 22")
    win._update_telemetry_views()
    assert win.port_gauge.open_ports == 1

    # Compound relational NQL query (ports 22 and 443 exist in DB)
    db.save_port_scan(PortScanRecord(mac=dev.mac, ip=dev.ip, port=80, service="http", banner="nginx"))
    win.nql_input.setText("srcport >= 80 AND dstport != 443 && proto == tcp")
    win._update_telemetry_views()
    assert win.port_gauge.open_ports == 1  # matches port 80, excludes 22 (<80) and 443 (!=443)

    win.nql_input.setText("dstip == 192.168.1.0/24 AND service != ssh")
    win._update_telemetry_views()
    assert win.port_gauge.open_ports == 2  # matches 80 and 443, excludes ssh (22)

    win.nql_input.setText("")
    win._update_telemetry_views()
    assert win.port_gauge.open_ports == 3

    # Test Analyze Metric selector ("bitrate", "packets", "flows")
    for metric_name in ("packets", "flows", "bitrate"):
        win.combo_analyze_metric.setCurrentText(metric_name)
        assert len(win.flows_spiral._intensities) == 96

    # Test synchronized hover across all 6 TelemetryAreaCharts
    win._on_telemetry_hover_changed(0.35)
    for ch in win._telemetry_charts:
        assert ch._hover_ratio == 0.35

    # Test compact laptop resolution resize (1024x600) & QPainter render pass
    win.resize(1024, 600)
    for widget in (
        win.port_gauge,
        win.packet_flow_chart,
        win.top_protocols_chart,
        win.flows_spiral,
        win.proto_breakdown_bar,
        win.port_breakdown_bar,
        win.tcp_flag_widget,
        win.timeline_slider,
        *win._telemetry_charts,
    ):
        shot = widget.grab()
        assert not shot.isNull()

    win._on_telemetry_hover_changed(None)
    win.close()


def test_traffic_monitor_no_fabricated_startup_waves_and_honest_labeling(tmp_path: Path) -> None:
    """Verify P1 #1 fix: TrafficMonitor does not fabricate startup sine waves or inflate counters by default."""
    import struct

    from src.core.traffic_monitor import TrafficMonitor
    from src.native.c_bridge import NativePacketEngine

    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "telemetry_honest.db")
    cfg = ConfigManager(tmp_path / "config.json")
    c_engine = NativePacketEngine(auto_compile=True)

    tm = TrafficMonitor(max_samples=60, demo_mode=False, c_engine=c_engine)
    # Startup baseline samples must all be zero (no fabricated historical sine wave)
    assert all(s.tcp_mbps == 0.0 and s.udp_mbps == 0.0 and s.bitrate_mbps == 0.0 for s in tm._samples)

    snap0 = tm.build_snapshot(db=db)
    assert snap0.is_estimated is True
    assert snap0.telemetry_mode == "ESTIMATED_NIC"
    assert "Estimated" in snap0.telemetry_label
    assert snap0.bits_per_sec_formatted == "0.00Mbps"

    # Ingest real Ethernet + IPv4 + TCP SYN+ACK packet via C engine
    eth_hdr = bytes.fromhex("50c7bf000001a434d91122330800")
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 1234, 0, 64, 6, 0,
        bytes([192, 168, 1, 10]),
        bytes([192, 168, 1, 1]),
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", 54321, 443, 1, 1, 0x50, 0x12, 65535, 0, 0)
    assert tm.ingest_raw_packet(eth_hdr + ip_hdr + tcp_hdr) is True

    snap_live = tm.record_tick(db=db)
    assert snap_live.is_estimated is False
    assert snap_live.telemetry_mode == "LIVE_PCAP"
    assert "Live Packet Capture" in snap_live.telemetry_label
    assert snap_live.samples[-1].tcp_flags.get("ACK SYN", 0.0) >= 1.0
    assert snap_live.protocol_breakdown[0] == ("tcp", 100.0, "#F59E0B")
    assert snap_live.port_breakdown[0][0] == "443 https"
    assert snap_live.port_breakdown[0][1] == 100.0

    # Verify MainWindow explicitly displays "Estimated" / "NIC Counters" on startup
    win = MainWindow(config=cfg, db=db)
    assert "Estimated" in win.lbl_packet_flow_title.text()
    assert "Estimated" in win.lbl_telemetry_badge.text()
    assert "Estimated" in win.lbl_telemetry_source_note.text()

    # Toggling Demo Telemetry explicitly marks UI as "Demo / Simulated"
    win.chk_demo_telemetry.setChecked(True)
    assert "Demo" in win.lbl_packet_flow_title.text()
    assert "Demo" in win.lbl_telemetry_badge.text()
    win.chk_demo_telemetry.setChecked(False)
    assert "Estimated" in win.lbl_packet_flow_title.text()
    win.close()


def test_appdata_writable_paths_when_cwd_unwritable(tmp_path: Path, monkeypatch) -> None:
    """Verify P1 #2 fix: relative log/DB/config paths resolve to writable AppData and never crash."""
    from src.utils.logger import get_app_data_dir, resolve_data_path, setup_logger

    custom_appdata = tmp_path / "AppDataTest"
    monkeypatch.setenv("LOCALAPPDATA", str(custom_appdata))
    monkeypatch.setenv("XDG_DATA_HOME", str(custom_appdata))

    app_dir = get_app_data_dir()
    assert app_dir == (custom_appdata / "NetworkSentry").resolve()
    assert app_dir.exists()

    log_resolved = resolve_data_path("networksentry.log")
    db_resolved = resolve_data_path("networksentry.db")
    assert log_resolved.parent == app_dir
    assert db_resolved.parent == app_dir

    # Initializing logger and DatabaseManager with relative paths writes to AppData, not CWD
    test_logger = setup_logger("TestUnwritableCwdLogger", log_file="networksentry.log")
    test_logger.info("Verification log entry from isolated AppData test")
    assert log_resolved.exists()

    db = DatabaseManager(db_path="networksentry.db")
    assert Path(db.check_health()["db_path"]).resolve() == db_resolved


