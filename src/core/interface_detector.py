"""Network interface and gateway detection across Windows and Linux."""

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Dict, List, Optional

import psutil

from src.database.models import NetworkInterfaceInfo
from src.utils.logger import setup_logger

logger = setup_logger("InterfaceDetector")


class InterfaceDetector:
    """Discovers local network interfaces, subnets, and the active default gateway."""

    @staticmethod
    def get_primary_outbound_ip() -> Optional[str]:
        """Determine the local IPv4 address used for default outbound routing."""
        for target in (("8.8.8.8", 80), ("1.1.1.1", 53)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1.0)
                    sock.connect(target)
                    return sock.getsockname()[0]
            except OSError:
                continue
        return None

    @staticmethod
    def get_default_gateways() -> Dict[str, str]:
        """
        Map local interface IPv4 address (or '*' for global) to its default gateway IPv4.
        Supports both Windows (`route print 0.0.0.0`) and Linux (`ip route` / `/proc/net/route`).
        """
        gateways: Dict[str, str] = {}
        system = platform.system().lower()

        if system == "windows":
            try:
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                proc = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    creationflags=creationflags,
                )
                # Match lines like: 0.0.0.0   0.0.0.0   192.168.1.1   192.168.1.42   25
                pattern = re.compile(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)"
                )
                for line in proc.stdout.splitlines():
                    match = pattern.match(line)
                    if match:
                        gw_ip, iface_ip = match.group(1), match.group(2)
                        gateways[iface_ip] = gw_ip
                        if "*" not in gateways:
                            gateways["*"] = gw_ip
            except Exception as exc:
                logger.debug("Windows route table query failed: %s", exc)
        else:
            try:
                proc = subprocess.run(
                    ["ip", "-4", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                # e.g. default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100
                for line in proc.stdout.splitlines():
                    via_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", line)
                    src_match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if via_match:
                        gw_ip = via_match.group(1)
                        gateways["*"] = gw_ip
                        if src_match:
                            gateways[src_match.group(1)] = gw_ip
            except Exception as exc:
                logger.debug("Linux route table query failed: %s", exc)

        return gateways

    @classmethod
    def list_interfaces(cls, include_loopback: bool = False) -> List[NetworkInterfaceInfo]:
        """List all IPv4-capable network interfaces with their MAC, CIDR, and gateway."""
        addrs_map = psutil.net_if_addrs()
        stats_map = psutil.net_if_stats()
        primary_ip = cls.get_primary_outbound_ip()
        gateways = cls.get_default_gateways()

        interfaces: List[NetworkInterfaceInfo] = []

        for iface_name, snic_list in addrs_map.items():
            ipv4_addr: Optional[str] = None
            netmask: Optional[str] = None
            mac_addr: str = "00:00:00:00:00:00"

            for snic in snic_list:
                if snic.family == socket.AF_INET:
                    ipv4_addr = snic.address
                    netmask = snic.netmask
                elif snic.family == psutil.AF_LINK:
                    raw_mac = snic.address.replace("-", ":").upper()
                    if len(raw_mac) == 17:
                        mac_addr = raw_mac

            if not ipv4_addr or not netmask:
                continue

            if not include_loopback and ipv4_addr.startswith("127."):
                continue

            # Ignore link-local APIPA addresses (169.254.x.x) unless primary
            if ipv4_addr.startswith("169.254.") and ipv4_addr != primary_ip:
                continue

            try:
                network = ipaddress.IPv4Network(f"{ipv4_addr}/{netmask}", strict=False)
                cidr = str(network)
            except ValueError:
                continue

            stat = stats_map.get(iface_name)
            is_up = bool(stat.isup) if stat else True
            speed = int(stat.speed) if stat else 0
            mtu = int(stat.mtu) if stat else 1500

            is_primary = ipv4_addr == primary_ip
            gateway_ip = gateways.get(ipv4_addr)
            if not gateway_ip and is_primary:
                gateway_ip = gateways.get("*")

            interfaces.append(
                NetworkInterfaceInfo(
                    name=iface_name,
                    ip_address=ipv4_addr,
                    netmask=netmask,
                    mac_address=mac_addr,
                    cidr=cidr,
                    gateway_ip=gateway_ip,
                    is_up=is_up,
                    is_primary=is_primary,
                    speed_mbps=speed,
                    mtu=mtu,
                )
            )

        # Sort so that primary interface comes first, followed by active interfaces with gateways
        interfaces.sort(
            key=lambda x: (x.is_primary, x.gateway_ip is not None, x.is_up, x.speed_mbps),
            reverse=True,
        )
        return interfaces

    @classmethod
    def get_active_interface(
        cls, preferred_name: Optional[str] = None
    ) -> Optional[NetworkInterfaceInfo]:
        """Return the preferred interface if available, or the best active primary interface."""
        interfaces = cls.list_interfaces(include_loopback=False)
        if not interfaces:
            return None

        if preferred_name:
            for iface in interfaces:
                if iface.name.lower() == preferred_name.lower():
                    return iface

        return interfaces[0]

