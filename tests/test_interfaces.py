"""Unit tests for network interface and gateway detection."""

import ipaddress

from src.core.interface_detector import InterfaceDetector
from src.database.models import NetworkInterfaceInfo


def test_list_interfaces_with_loopback() -> None:
    """Verify that listing interfaces returns valid NetworkInterfaceInfo models."""
    interfaces = InterfaceDetector.list_interfaces(include_loopback=True)
    assert len(interfaces) >= 1

    for iface in interfaces:
        assert isinstance(iface, NetworkInterfaceInfo)
        assert iface.name
        # Validate IP and CIDR format
        ipaddress.IPv4Address(iface.ip_address)
        ipaddress.IPv4Network(iface.cidr, strict=False)
        assert len(iface.mac_address) == 17


def test_get_active_interface() -> None:
    """Verify that active interface detection returns a valid primary interface when connected."""
    active = InterfaceDetector.get_active_interface()
    if active is not None:
        assert isinstance(active, NetworkInterfaceInfo)
        assert not active.ip_address.startswith("127.")
        assert "/" in active.cidr


def test_get_default_gateways_returns_dict() -> None:
    """Verify that gateway detection returns a dictionary of valid IPv4 addresses."""
    gateways = InterfaceDetector.get_default_gateways()
    assert isinstance(gateways, dict)
    for key, gw_ip in gateways.items():
        ipaddress.IPv4Address(gw_ip)
        if key != "*":
            ipaddress.IPv4Address(key)


def test_parse_proc_net_route_and_linux_fallback(tmp_path, monkeypatch) -> None:
    """Verify /proc/net/route hex parsing and automatic fallback when `ip -4 route` is unavailable."""
    sample_proc_route = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        "wlan0\t00000000\tFE0010AC\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "docker0\t00000000\t010011AC\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
    )
    proc_file = tmp_path / "route"
    proc_file.write_text(sample_proc_route, encoding="utf-8")

    parsed = InterfaceDetector.parse_proc_net_route(proc_file)
    assert parsed["*"] == "192.168.1.1"
    assert parsed["eth0"] == "192.168.1.1"
    assert parsed["wlan0"] == "172.16.0.254"
    # docker0 has Flags=0001 (missing RTF_GATEWAY=0x2), so it must be ignored
    assert "docker0" not in parsed

    # Simulate minimal Linux environment where `ip` binary is missing (raises FileNotFoundError)
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Linux")

    def _raise_fnf(*args, **kwargs):
        raise FileNotFoundError("ip command not found")

    monkeypatch.setattr(subprocess, "run", _raise_fnf)
    gw_fallback = InterfaceDetector.get_default_gateways(proc_route_path=proc_file)
    assert gw_fallback.get("*") == "192.168.1.1"

    # Big-endian /proc/net/route hex layout (C0A80101 -> 192.168.1.1)
    sample_be = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\tC0A80101\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
    )
    parsed_be = InterfaceDetector.parse_proc_net_route(sample_be, byteorder="big")
    assert parsed_be["*"] == "192.168.1.1"
    assert parsed_be["eth0"] == "192.168.1.1"


def test_primary_outbound_ip_uses_routing_table_without_external_ips(monkeypatch) -> None:
    """Verify that get_primary_outbound_ip never connects to external IPs like 8.8.8.8 or 1.1.1.1 and prefers UP interfaces."""
    import socket
    from types import SimpleNamespace

    class GuardedSocket(socket.socket):
        def connect(self, address):
            host = address[0] if isinstance(address, tuple) else str(address)
            assert host not in ("8.8.8.8", "1.1.1.1"), f"Unexpected external probe to {host}"
            return super().connect(address)

    monkeypatch.setattr(socket, "socket", GuardedSocket)
    ip = InterfaceDetector.get_primary_outbound_ip()
    assert isinstance(ip, str)
    ipaddress.IPv4Address(ip)

    # Verify DOWN interface in gateways is skipped in favor of UP interface
    fake_addrs = {
        "eth_down": [SimpleNamespace(family=socket.AF_INET, address="10.0.0.5", netmask="255.255.255.0")],
        "wlan_up": [SimpleNamespace(family=socket.AF_INET, address="192.168.1.42", netmask="255.255.255.0")],
    }
    fake_stats = {
        "eth_down": SimpleNamespace(isup=False, speed=1000, mtu=1500),
        "wlan_up": SimpleNamespace(isup=True, speed=866, mtu=1500),
    }
    fake_gws = {"*": "10.0.0.1", "10.0.0.5": "10.0.0.1", "192.168.1.42": "192.168.1.1"}
    chosen = InterfaceDetector.get_primary_outbound_ip(
        gateways=fake_gws,
        addrs_map=fake_addrs,
        stats_map=fake_stats,
    )
    assert chosen == "192.168.1.42"


