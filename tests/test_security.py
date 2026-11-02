"""Unit tests for Phase 3: Security Engine (ARP Spoof Detector, Port Scanner, Risk Engine)."""

import socket
import threading
from pathlib import Path

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, PortScanRecord
from src.security.arp_spoof_detector import ARPSpoofDetector
from src.security.port_scanner import PortScanner
from src.security.risk_engine import RiskEngine


def test_arp_spoof_detector_gateway_mac_lock_and_tamper(tmp_path: Path) -> None:
    """Verify gateway MAC lock-in and CRITICAL alert when gateway MAC changes."""
    db = DatabaseManager(db_path=tmp_path / "spoof1.db")
    detector = ARPSpoofDetector(lock_gateway_mac=True)

    # Cycle 1: Normal baseline (Gateway 192.168.1.1 -> 50:C7:BF:00:00:01)
    ip_to_macs_1 = {
        "192.168.1.1": {"50:C7:BF:00:00:01"},
        "192.168.1.10": {"A4:34:D9:11:22:33"},
    }
    alerts_1 = detector.analyze_scan(ip_to_macs_1, [], gateway_ip="192.168.1.1", db=db)
    assert len(alerts_1) == 0
    assert detector.locked_gateway_mac == "50:C7:BF:00:00:01"

    # Cycle 2: Attacker replaces Gateway MAC with DE:AD:BE:EF:00:99
    ip_to_macs_2 = {
        "192.168.1.1": {"DE:AD:BE:EF:00:99"},
        "192.168.1.10": {"A4:34:D9:11:22:33"},
    }
    alerts_2 = detector.analyze_scan(ip_to_macs_2, [], gateway_ip="192.168.1.1", db=db)
    assert len(alerts_2) == 1
    assert alerts_2[0].alert_type == "ARP_SPOOFING"
    assert alerts_2[0].severity == "CRITICAL"
    assert alerts_2[0].mac == "DE:AD:BE:EF:00:99"

    saved_alerts = db.get_alerts(unresolved_only=True)
    assert len(saved_alerts) == 1


def test_arp_spoof_detector_duplicate_ip_and_gateway_clone() -> None:
    """Verify detection of multiple MACs per IP and a single MAC impersonating the gateway."""
    detector = ARPSpoofDetector(lock_gateway_mac=True)
    detector.set_gateway("192.168.1.1", "50:C7:BF:00:00:01")

    # Scenario A: Two MACs claiming 192.168.1.1 simultaneously
    ip_to_macs_dup = {
        "192.168.1.1": {"50:C7:BF:00:00:01", "AA:BB:CC:DD:EE:99"},
    }
    alerts_dup = detector.analyze_scan(ip_to_macs_dup, [], gateway_ip="192.168.1.1")
    assert any(a.alert_type == "ARP_SPOOFING" and a.severity == "CRITICAL" for a in alerts_dup)

    # Scenario B: Attacker at 192.168.1.66 also claims 192.168.1.1 with same MAC in ARP cache
    ip_to_macs_clone = {
        "192.168.1.1": {"50:C7:BF:00:00:01"},
        "192.168.1.66": {"50:C7:BF:00:00:01"},
    }
    alerts_clone = detector.analyze_scan(ip_to_macs_clone, [], gateway_ip="192.168.1.1")
    assert any(a.alert_type == "ARP_SPOOFING" and a.severity == "CRITICAL" for a in alerts_clone)


def test_arp_spoof_live_packet_inspection() -> None:
    """Verify packet-level ARP inspection for gratuitous ARP and gateway spoofing."""
    detector = ARPSpoofDetector(lock_gateway_mac=True)
    detector.set_gateway("192.168.1.1", "50:C7:BF:00:00:01")

    # Authentic gateway packet -> no alert
    ok = detector.inspect_arp_packet(
        src_mac="50:C7:BF:00:00:01",
        src_ip="192.168.1.1",
        dst_mac="FF:FF:FF:FF:FF:FF",
        dst_ip="192.168.1.1",
        opcode=2,
        is_gratuitous=True,
    )
    assert ok is None

    # Spoofed gratuitous ARP reply claiming gateway IP -> CRITICAL alert
    spoof = detector.inspect_arp_packet(
        src_mac="00:11:22:33:44:55",
        src_ip="192.168.1.1",
        dst_mac="FF:FF:FF:FF:FF:FF",
        dst_ip="192.168.1.1",
        opcode=2,
        is_gratuitous=True,
    )
    assert spoof is not None
    assert spoof.alert_type == "ARP_SPOOFING"
    assert spoof.severity == "CRITICAL"

    # L2/L3 MAC header mismatch: attacker forges gateway MAC in ARP payload but sends from DE:AD:BE:EF:99:99
    mismatch_alert = detector.inspect_arp_packet(
        src_mac="50:C7:BF:00:00:01",
        src_ip="192.168.1.1",
        dst_mac="FF:FF:FF:FF:FF:FF",
        dst_ip="192.168.1.1",
        opcode=2,
        is_gratuitous=True,
        eth_src_mac="DE:AD:BE:EF:99:99",
        mac_mismatch=True,
    )
    assert mismatch_alert is not None
    assert mismatch_alert.alert_type == "ARP_SPOOFING"
    assert mismatch_alert.severity == "CRITICAL"
    assert mismatch_alert.mac == "DE:AD:BE:EF:99:99"


def test_port_scanner_with_local_tcp_listener(tmp_path: Path) -> None:
    """Verify concurrent TCP port scanning, banner grabbing, and pruning closed ports on rescan."""
    db = DatabaseManager(db_path=tmp_path / "ports.db")
    mac = "AA:BB:CC:11:22:33"
    db.upsert_device(DeviceRecord(mac=mac, ip="127.0.0.1"))

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(2)
    open_port = server_sock.getsockname()[1]

    # Pick a closed port and seed it in DB as previously open to verify stale-port cleanup
    closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_sock.bind(("127.0.0.1", 0))
    closed_port = closed_sock.getsockname()[1]
    closed_sock.close()
    db.save_port_scan(PortScanRecord(mac=mac, ip="127.0.0.1", port=closed_port, service="telnet"))
    assert len(db.get_device_ports(mac)) == 1

    def _serve_once() -> None:
        try:
            conn, _ = server_sock.accept()
            with conn:
                conn.sendall(b"SSH-2.0-NetworkSentryTest\r\n")
        except OSError:
            pass
        finally:
            server_sock.close()

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()

    scanner = PortScanner(timeout=0.5, grab_banners=True)
    results = scanner.scan_host("127.0.0.1", mac=mac, ports=[open_port, closed_port], db=db)
    t.join(timeout=2.0)

    assert len(results) == 1
    assert results[0].port == open_port
    assert results[0].state == "OPEN"
    assert "SSH-2.0-NetworkSentryTest" in results[0].banner

    # Previously open `closed_port` must be pruned from SQLite on rescan
    saved_ports = db.get_device_ports(mac)
    assert len(saved_ports) == 1
    assert saved_ports[0].port == open_port


def test_risk_engine_classification_tiers(tmp_path: Path) -> None:
    """Verify LOW, MEDIUM, HIGH, and CRITICAL risk scoring tiers."""
    db = DatabaseManager(db_path=tmp_path / "risk.db")
    engine = RiskEngine()

    # 1. Trusted device with standard HTTP/HTTPS ports -> LOW
    dev_trusted = DeviceRecord(
        mac="50:C7:BF:00:00:01",
        ip="192.168.1.1",
        vendor="TP-Link Technologies Co., Ltd.",
        is_trusted=True,
    )
    db.upsert_device(dev_trusted)
    res_low = engine.evaluate_device(
        dev_trusted,
        open_ports=[PortScanRecord(mac=dev_trusted.mac, ip=dev_trusted.ip, port=80, service="http")],
        db=db,
    )
    assert res_low.risk_level == "LOW"
    assert res_low.risk_score < 30

    # 2. New untrusted device with Randomized MAC -> MEDIUM
    dev_medium = DeviceRecord(
        mac="DA:A1:19:10:20:30",
        ip="192.168.1.45",
        vendor="Randomized / Private MAC",
        is_trusted=False,
    )
    db.upsert_device(dev_medium)
    res_med = engine.evaluate_device(dev_medium, is_new_device=True, db=db)
    assert res_med.risk_level == "MEDIUM"
    assert 30 <= res_med.risk_score < 60

    # 3. Untrusted device exposing Telnet (23) and SMB (445) -> HIGH
    dev_high = DeviceRecord(
        mac="00:11:22:AA:BB:CC",
        ip="192.168.1.88",
        vendor="Unknown Vendor",
        is_trusted=False,
    )
    db.upsert_device(dev_high)
    res_high = engine.evaluate_device(
        dev_high,
        open_ports=[
            PortScanRecord(mac=dev_high.mac, ip=dev_high.ip, port=23, service="telnet"),
            PortScanRecord(mac=dev_high.mac, ip=dev_high.ip, port=445, service="microsoft-ds"),
        ],
        db=db,
    )
    assert res_high.risk_level in ("HIGH", "CRITICAL")
    assert res_high.risk_score >= 60
    assert len(res_high.alerts) == 2

    # 4. Device involved in ARP Spoofing -> CRITICAL
    from src.database.models import SecurityAlertRecord

    spoof_alert = SecurityAlertRecord(
        alert_type="ARP_SPOOFING",
        severity="CRITICAL",
        mac=dev_medium.mac,
        ip=dev_medium.ip,
        description="Gateway MAC spoofed",
    )
    res_crit = engine.evaluate_device(dev_medium, active_alerts=[spoof_alert], db=db)
    assert res_crit.risk_level == "CRITICAL"
    assert res_crit.risk_score >= 90
