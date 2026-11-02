"""Unit tests for Phase 2: Device Discovery (OUI Lookup, ARP Scanner, State Diffing)."""

from pathlib import Path
from typing import Dict, List, Set, Tuple

from src.core.arp_scanner import ARPScanner
from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, NetworkInterfaceInfo
from src.utils.oui_lookup import OUILookup


def test_oui_mac_normalization_and_validation() -> None:
    """Verify MAC normalization across colon, hyphen, dot, and single-digit octet formats."""
    assert OUILookup.normalize_mac("00-11-24-aa-bb-cc") == "00:11:24:AA:BB:CC"
    assert OUILookup.normalize_mac("0011.24aa.bbcc") == "00:11:24:AA:BB:CC"
    assert OUILookup.normalize_mac("0:3:93:a:b:c") == "00:03:93:0A:0B:0C"
    assert OUILookup.normalize_mac("  B8:27:EB:01:02:03 ") == "B8:27:EB:01:02:03"

    assert OUILookup.normalize_mac("") == ""
    assert OUILookup.normalize_mac("invalid-mac") == ""
    assert OUILookup.normalize_mac("00:11:22:33:44") == ""
    assert OUILookup.normalize_mac("00:11:22:33:44:55:66") == ""

    assert OUILookup.is_valid_mac("00:11:24:AA:BB:CC") is True
    assert OUILookup.is_valid_mac("00:00:00:00:00:00") is False
    assert OUILookup.is_valid_mac("not-a-mac") is False


def test_oui_vendor_lookup_and_randomized_mac_detection() -> None:
    """Verify offline OUI vendor resolution, multicast/broadcast, and randomized LAA MACs."""
    oui = OUILookup()
    assert oui.count >= 100

    assert "Apple" in oui.lookup("00:03:93:12:34:56")
    assert "Raspberry Pi" in oui.lookup("B8-27-EB-AA-BB-CC")
    assert "Espressif" in oui.lookup("24:0A:C4:99:88:77")
    assert "VMware" in oui.lookup("00:50:56:01:02:03")

    # Known virtual LAA prefixes should not be flagged as randomized mobile MACs
    assert oui.is_randomized_mac("02:42:AC:11:00:02") is False
    assert "Docker" in oui.lookup("02:42:AC:11:00:02")
    assert oui.is_randomized_mac("52:54:00:12:34:56") is False
    assert "QEMU" in oui.lookup("52:54:00:12:34:56")

    # Randomized / Locally Administered unicast MACs (2nd hex digit is 2, 6, A, E)
    assert oui.is_randomized_mac("DA:A1:19:44:55:66") is True
    assert oui.lookup("DA:A1:19:44:55:66") == "Randomized / Private MAC"

    # Special addresses
    assert oui.lookup("FF:FF:FF:FF:FF:FF") == "Broadcast"
    assert oui.lookup("01:00:5E:00:00:FB") == "IPv4 Multicast"
    assert oui.lookup("33:33:00:00:00:16") == "IPv6 Multicast"
    assert oui.lookup("00:00:00:00:00:00") == "Unknown Vendor"


def test_arp_table_parser_windows_and_linux_formats() -> None:
    """Verify parsing of both Windows `arp -a` and Linux `/proc/net/arp` outputs."""
    sample_output = """
Interface: 192.168.1.42 --- 0xc
  Internet Address      Physical Address      Type
  192.168.1.1           50-c7-bf-11-22-33     dynamic
  192.168.1.15          00-03-93-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.251           01-00-5e-00-00-fb     static
  192.168.1.99          00:00:00:00:00:00     incomplete
  192.168.1.50          b8:27:eb:10:20:30     0x1 0x2 eth0
"""
    parsed = ARPScanner.read_os_arp_table(arp_output=sample_output)
    assert set(parsed.keys()) == {"192.168.1.1", "192.168.1.15", "192.168.1.50"}
    assert parsed["192.168.1.1"] == {"50:C7:BF:11:22:33"}
    assert parsed["192.168.1.15"] == {"00:03:93:AA:BB:CC"}
    assert parsed["192.168.1.50"] == {"B8:27:EB:10:20:30"}


def test_get_target_hosts_scoping() -> None:
    """Verify CIDR host calculation and /16 to /24 scoping."""
    hosts_29 = ARPScanner.get_target_hosts("192.168.1.0/29")
    assert len(hosts_29) == 6
    assert hosts_29[0] == "192.168.1.1"
    assert hosts_29[-1] == "192.168.1.6"

    # Large /16 network should scope around local_ip /24
    hosts_16 = ARPScanner.get_target_hosts("172.16.0.0/16", local_ip="172.16.42.10")
    assert len(hosts_16) == 254
    assert hosts_16[0] == "172.16.42.1"
    assert hosts_16[-1] == "172.16.42.254"


def test_discovery_scan_and_sync_state_lifecycle(tmp_path: Path, monkeypatch) -> None:
    """Verify full device discovery, new device alerts, IP changes, and offline/reconnected history."""
    db = DatabaseManager(db_path=tmp_path / "discovery_test.db")
    scanner = ARPScanner(resolve_hostnames=False)

    iface = NetworkInterfaceInfo(
        name="Wi-Fi",
        ip_address="192.168.1.10",
        netmask="255.255.255.0",
        mac_address="A4:34:D9:11:22:33",
        cidr="192.168.1.0/24",
        gateway_ip="192.168.1.1",
        is_primary=True,
    )

    # Cycle 1: Gateway + Local PC + Phone + Raspberry Pi
    def mock_scan_cycle_1(
        interface: NetworkInterfaceInfo, progress_callback=None
    ) -> Tuple[List[DeviceRecord], Dict[str, Set[str]]]:
        devs = [
            DeviceRecord(
                mac="50:C7:BF:00:00:01",
                ip="192.168.1.1",
                hostname="Default-Gateway",
                vendor="TP-Link Technologies Co., Ltd.",
                is_trusted=True,
            ),
            DeviceRecord(
                mac="A4:34:D9:11:22:33",
                ip="192.168.1.10",
                hostname="workstation",
                vendor="Intel Corporate",
                is_trusted=True,
            ),
            DeviceRecord(
                mac="00:03:93:AA:BB:01",
                ip="192.168.1.25",
                hostname="iphone",
                vendor="Apple, Inc.",
                is_trusted=False,
            ),
            DeviceRecord(
                mac="B8:27:EB:CC:DD:02",
                ip="192.168.1.30",
                hostname="raspberrypi",
                vendor="Raspberry Pi Foundation",
                is_trusted=False,
            ),
        ]
        ip_map = {d.ip: {d.mac} for d in devs}
        return devs, ip_map

    monkeypatch.setattr(scanner, "scan_subnet", mock_scan_cycle_1)
    res1 = scanner.scan_and_sync(iface, db, alert_on_new_device=True)

    assert len(res1.discovered_devices) == 4
    assert len(res1.new_devices) == 4
    # Only the 2 untrusted devices should trigger NEW_DEVICE alerts
    assert len(res1.alerts_created) == 2
    assert res1.went_offline_count == 0

    # Cycle 2: Phone changes IP to .26, Raspberry Pi goes offline
    def mock_scan_cycle_2(
        interface: NetworkInterfaceInfo, progress_callback=None
    ) -> Tuple[List[DeviceRecord], Dict[str, Set[str]]]:
        devs = [
            DeviceRecord(
                mac="50:C7:BF:00:00:01",
                ip="192.168.1.1",
                hostname="Default-Gateway",
                vendor="TP-Link Technologies Co., Ltd.",
                is_trusted=True,
            ),
            DeviceRecord(
                mac="A4:34:D9:11:22:33",
                ip="192.168.1.10",
                hostname="workstation",
                vendor="Intel Corporate",
                is_trusted=True,
            ),
            DeviceRecord(
                mac="00:03:93:AA:BB:01",
                ip="192.168.1.26",
                hostname="iphone",
                vendor="Apple, Inc.",
                is_trusted=False,
            ),
        ]
        ip_map = {d.ip: {d.mac} for d in devs}
        return devs, ip_map

    monkeypatch.setattr(scanner, "scan_subnet", mock_scan_cycle_2)
    res2 = scanner.scan_and_sync(iface, db, alert_on_new_device=True)

    assert len(res2.new_devices) == 0
    assert len(res2.ip_changed_devices) == 1
    assert res2.ip_changed_devices[0][0].mac == "00:03:93:AA:BB:01"
    assert res2.ip_changed_devices[0][1] == "192.168.1.25"
    assert res2.went_offline_count == 1

    # Check history events
    phone_history = db.get_device_history("00:03:93:AA:BB:01")
    event_types = [h.event_type for h in phone_history]
    assert "FIRST_SEEN" in event_types
    assert "IP_CHANGED" in event_types

    pi_history = db.get_device_history("B8:27:EB:CC:DD:02")
    assert [h.event_type for h in pi_history] == ["OFFLINE", "FIRST_SEEN"]
