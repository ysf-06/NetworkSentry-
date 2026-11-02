"""Unit tests for SQLite DatabaseManager and data models."""

from pathlib import Path

from src.database.db_manager import DatabaseManager
from src.database.models import (
    DeviceRecord,
    PortScanRecord,
    ScanSessionRecord,
    SecurityAlertRecord,
)


def test_database_initialization_and_wal_mode(tmp_path: Path) -> None:
    """Verify schema creation and WAL journal mode."""
    db_file = tmp_path / "test_sentry.db"
    db = DatabaseManager(db_path=db_file, wal_mode=True)

    health = db.check_health()
    assert health["is_healthy"] is True
    assert health["journal_mode"].lower() == "wal"
    assert set(health["tables"]) >= {
        "devices",
        "device_history",
        "security_alerts",
        "port_scans",
        "scan_sessions",
    }


def test_device_upsert_and_ip_change_tracking(tmp_path: Path) -> None:
    """Verify inserting a device, updating its IP, and tracking online/offline state."""
    db = DatabaseManager(db_path=tmp_path / "devices.db")

    dev1 = DeviceRecord(
        mac="aa:bb:cc:dd:ee:01",
        ip="192.168.1.15",
        hostname="yusuf-phone",
        vendor="Apple, Inc.",
    )
    is_new, prev_ip = db.upsert_device(dev1)
    assert is_new is True
    assert prev_ip is None

    # Fetch and check MAC normalization
    saved = db.get_device_by_mac("aa:bb:cc:dd:ee:01")
    assert saved is not None
    assert saved.mac == "AA:BB:CC:DD:EE:01"
    assert saved.ip == "192.168.1.15"
    assert saved.vendor == "Apple, Inc."

    # Update with new IP
    dev1_updated = DeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.99",
    )
    is_new_2, prev_ip_2 = db.upsert_device(dev1_updated)
    assert is_new_2 is False
    assert prev_ip_2 == "192.168.1.15"

    saved_after = db.get_device_by_mac("AA:BB:CC:DD:EE:01")
    assert saved_after is not None
    assert saved_after.ip == "192.168.1.99"
    # Existing hostname and vendor should be preserved when not overridden
    assert saved_after.hostname == "yusuf-phone"
    assert saved_after.vendor == "Apple, Inc."


def test_mark_offline_and_trusted_and_risk(tmp_path: Path) -> None:
    """Verify offline marking, trust toggling, and risk updates."""
    db = DatabaseManager(db_path=tmp_path / "state.db")

    db.upsert_device(DeviceRecord(mac="11:22:33:44:55:01", ip="192.168.1.10"))
    db.upsert_device(DeviceRecord(mac="11:22:33:44:55:02", ip="192.168.1.11"))

    offline_count = db.mark_offline_devices(["11:22:33:44:55:01"])
    assert offline_count == 1

    online_devs = db.get_all_devices(online_only=True)
    assert len(online_devs) == 1
    assert online_devs[0].mac == "11:22:33:44:55:01"

    db.set_device_trusted("11:22:33:44:55:01", True)
    db.update_device_risk("11:22:33:44:55:02", "HIGH", 85)

    stats = db.get_dashboard_stats()
    assert stats["total_devices"] == 2
    assert stats["online_devices"] == 1
    assert stats["offline_devices"] == 1
    assert stats["trusted_devices"] == 1
    assert stats["high_risk_devices"] == 1


def test_alerts_and_port_scans_and_sessions(tmp_path: Path) -> None:
    """Verify recording security alerts, open ports, and scan sessions."""
    db = DatabaseManager(db_path=tmp_path / "security.db")
    db.upsert_device(DeviceRecord(mac="AA:BB:CC:00:11:22", ip="192.168.1.50"))

    alert_id = db.record_alert(
        SecurityAlertRecord(
            alert_type="ARP_SPOOFING",
            severity="CRITICAL",
            mac="AA:BB:CC:00:11:22",
            ip="192.168.1.1",
            description="Duplicate gateway MAC detected",
        )
    )
    assert alert_id >= 1

    alerts = db.get_alerts(unresolved_only=True)
    assert len(alerts) == 1
    assert alerts[0].alert_type == "ARP_SPOOFING"

    db.save_port_scan(
        PortScanRecord(
            mac="AA:BB:CC:00:11:22",
            ip="192.168.1.50",
            port=22,
            service="ssh",
            banner="OpenSSH_9.0",
        )
    )
    ports = db.get_device_ports("AA:BB:CC:00:11:22")
    assert len(ports) == 1
    assert ports[0].port == 22
    assert ports[0].banner == "OpenSSH_9.0"

    session_id = db.create_scan_session(
        ScanSessionRecord(
            interface_name="Wi-Fi",
            subnet_cidr="192.168.1.0/24",
            gateway_ip="192.168.1.1",
        )
    )
    db.finish_scan_session(session_id, devices_found=5, new_devices=2, alerts_triggered=1)
