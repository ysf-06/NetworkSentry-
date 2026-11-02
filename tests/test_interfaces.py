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

