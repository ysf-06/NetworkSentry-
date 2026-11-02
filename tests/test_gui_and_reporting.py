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
    assert any(a.alert_type == "ARP_SPOOFING" and a.severity == "CRITICAL" for a in alerts)
    attacker = db.get_device_by_mac("DE:AD:BE:EF:CA:FE")
    assert attacker is not None
    assert attacker.risk_level == "CRITICAL"

    # Export CSV & JSON via MainWindow
    csv_out = win.export_csv_report(tmp_path / "gui_export.csv")
    json_out = win.export_json_report(tmp_path / "gui_export.json")
    assert csv_out is not None and csv_out.exists()
    assert json_out is not None and json_out.exists()

    # Resolve all alerts
    win.resolve_all_alerts()
    assert len(db.get_alerts(unresolved_only=True)) == 0
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
