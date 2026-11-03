"""Network interface and gateway detection across Windows and Linux."""

import ipaddress
import platform
import re
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil

from src.database.models import NetworkInterfaceInfo
from src.utils.logger import setup_logger

logger = setup_logger("InterfaceDetector")


class InterfaceDetector:
    """Discovers local network interfaces, subnets, and the active default gateway."""

    @staticmethod
    def _extract_iface_ipv4_map(addrs_map: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """Build a mapping of `interface_name -> ipv4_address` from psutil interface addresses."""
        if addrs_map is None:
            try:
                addrs_map = psutil.net_if_addrs()
            except Exception:
                return {}
        iface_ips: Dict[str, str] = {}
        for iface_name, snic_list in addrs_map.items():
            for snic in snic_list:
                if getattr(snic, "family", None) == socket.AF_INET and getattr(snic, "address", None):
                    iface_ips[iface_name] = snic.address
                    break
        return iface_ips

    @staticmethod
    def parse_proc_net_route(
        route_source: str | Path,
        iface_ip_map: Optional[Dict[str, str]] = None,
        byteorder: str = "little",
    ) -> Dict[str, str]:
        """
        Parse Linux `/proc/net/route` content (or file path) to extract default gateways (`Destination == 00000000`).
        When `iface_ip_map` is provided, maps interface IPv4 -> gateway IPv4 (plus `'*'`).
        When `iface_ip_map` is None, maps interface name -> gateway IPv4 (plus `'*'`).
        """
        gateways: Dict[str, str] = {}
        if not route_source:
            return gateways

        if isinstance(route_source, Path):
            try:
                route_text = route_source.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return gateways
        elif "\n" not in route_source and Path(route_source).exists():
            try:
                route_text = Path(route_source).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return gateways
        else:
            route_text = str(route_source)

        pack_fmt = ">I" if str(byteorder).lower().startswith("big") else "<I"
        candidates: List[Tuple[int, str, str]] = []
        lines = route_text.strip().splitlines()
        for line in lines[1:]:  # Skip header line
            parts = line.strip().split()
            if len(parts) < 8:
                continue
            iface_name, dest_hex, gw_hex, flags_hex = parts[0], parts[1], parts[2], parts[3]
            metric_str = parts[6]
            if dest_hex != "00000000" or gw_hex == "00000000":
                continue
            try:
                flags = int(flags_hex, 16)
                # Both RTF_UP (0x1) and RTF_GATEWAY (0x2) must be set for an active default gateway
                if (flags & 0x0003) != 0x0003:
                    continue
                gw_int = int(gw_hex, 16)
                gw_ip = socket.inet_ntoa(struct.pack(pack_fmt, gw_int))
                ipaddress.IPv4Address(gw_ip)
                metric = int(metric_str) if metric_str.isdigit() else 100
                candidates.append((metric, iface_name, gw_ip))
            except (ValueError, struct.error, OSError):
                continue

        candidates.sort(key=lambda item: item[0])
        for _, iface_name, gw_ip in candidates:
            if "*" not in gateways:
                gateways["*"] = gw_ip
            if iface_ip_map is not None:
                if iface_name in iface_ip_map:
                    iface_ip = iface_ip_map[iface_name]
                    gateways.setdefault(iface_ip, gw_ip)
            else:
                gateways.setdefault(iface_name, gw_ip)

        return gateways

    @classmethod
    def get_default_gateways(
        cls,
        addrs_map: Optional[Dict[str, Any]] = None,
        proc_route_path: str | Path = "/proc/net/route",
    ) -> Dict[str, str]:
        """
        Map local interface IPv4 address (or '*' for global) to its default gateway IPv4.
        Supports Windows (`route print 0.0.0.0`) and Linux (`ip -4 route` with `/proc/net/route` fallback).
        """
        gateways: Dict[str, str] = {}
        system = platform.system().lower()
        iface_ip_map = cls._extract_iface_ipv4_map(addrs_map)

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
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?"
                )
                win_routes: List[Tuple[int, str, str]] = []
                for line in proc.stdout.splitlines():
                    match = pattern.match(line)
                    if match:
                        gw_ip, iface_ip, metric_raw = match.group(1), match.group(2), match.group(3)
                        metric = int(metric_raw) if (metric_raw and metric_raw.isdigit()) else 100
                        win_routes.append((metric, iface_ip, gw_ip))
                win_routes.sort(key=lambda item: item[0])
                for _, iface_ip, gw_ip in win_routes:
                    gateways.setdefault(iface_ip, gw_ip)
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
                if proc.returncode == 0 and proc.stdout:
                    linux_routes: List[Tuple[int, Optional[str], str]] = []
                    for line in proc.stdout.splitlines():
                        via_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", line)
                        src_match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", line)
                        dev_match = re.search(r"dev\s+(\S+)", line)
                        metric_match = re.search(r"metric\s+(\d+)", line)
                        if via_match:
                            gw_ip = via_match.group(1)
                            metric = int(metric_match.group(1)) if metric_match else 100
                            route_ip: Optional[str] = None
                            if src_match:
                                route_ip = src_match.group(1)
                            elif dev_match and dev_match.group(1) in iface_ip_map:
                                route_ip = iface_ip_map[dev_match.group(1)]
                            linux_routes.append((metric, route_ip, gw_ip))
                    linux_routes.sort(key=lambda item: item[0])
                    for _, r_ip, gw_ip in linux_routes:
                        if "*" not in gateways:
                            gateways["*"] = gw_ip
                        if r_ip:
                            gateways.setdefault(r_ip, gw_ip)
            except Exception as exc:
                logger.debug("Linux ip route query failed (falling back to /proc/net/route): %s", exc)

            # Fallback to /proc/net/route if `ip` was unavailable or returned no default gateway
            if "*" not in gateways:
                route_file = Path(proc_route_path)
                if route_file.exists():
                    try:
                        route_text = route_file.read_text(encoding="utf-8", errors="ignore")
                        fallback_gws = cls.parse_proc_net_route(route_text, iface_ip_map=iface_ip_map)
                        gateways.update(fallback_gws)
                    except OSError as exc:
                        logger.debug("Linux /proc/net/route fallback failed: %s", exc)

        return gateways

    @classmethod
    def get_primary_outbound_ip(
        cls,
        gateways: Optional[Dict[str, str]] = None,
        addrs_map: Optional[Dict[str, Any]] = None,
        stats_map: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Determine the primary local IPv4 address using the OS routing table first,
        then matching default gateway subnet, and finally active local NIC state.
        Does NOT probe external public IPs (like 8.8.8.8 or 1.1.1.1), preventing
        offline timeouts and external traffic leakage.
        """
        if addrs_map is None:
            try:
                addrs_map = psutil.net_if_addrs()
            except Exception:
                addrs_map = {}
        if stats_map is None:
            try:
                stats_map = psutil.net_if_stats()
            except Exception:
                stats_map = {}
        if gateways is None:
            gateways = cls.get_default_gateways(addrs_map=addrs_map)

        # Build set of active (UP) interface IPv4s if addrs_map is available
        up_ips: set[str] = set()
        known_ips: set[str] = set()
        for iface_name, snic_list in addrs_map.items():
            stat = stats_map.get(iface_name)
            is_up = bool(stat.isup) if stat else True
            for snic in snic_list:
                if getattr(snic, "family", None) == socket.AF_INET and getattr(snic, "address", None):
                    known_ips.add(snic.address)
                    if is_up:
                        up_ips.add(snic.address)

        # 1. Direct interface IPv4 entry from the OS default route table (preferring UP interfaces)
        fallback_gw_key: Optional[str] = None
        for key in gateways:
            if key != "*":
                try:
                    ipaddress.IPv4Address(key)
                    if not known_ips or key in up_ips:
                        return key
                    if fallback_gw_key is None:
                        fallback_gw_key = key
                except ValueError:
                    continue

        # 2. Match global default gateway IPv4 ('*') to a local interface's subnet
        default_gw = gateways.get("*")
        candidates: List[Tuple[bool, bool, int, str]] = []
        for iface_name, snic_list in addrs_map.items():
            ipv4_addr: Optional[str] = None
            netmask: Optional[str] = None
            for snic in snic_list:
                if getattr(snic, "family", None) == socket.AF_INET:
                    ipv4_addr = snic.address
                    netmask = snic.netmask
                    break
            if not ipv4_addr or not netmask or ipv4_addr.startswith("127.") or ipv4_addr.startswith("169.254."):
                continue

            stat = stats_map.get(iface_name)
            is_up = bool(stat.isup) if stat else True
            speed = int(stat.speed) if stat else 0

            try:
                net = ipaddress.IPv4Network(f"{ipv4_addr}/{netmask}", strict=False)
                ip_obj = ipaddress.IPv4Address(ipv4_addr)
                if default_gw and is_up and ipaddress.IPv4Address(default_gw) in net:
                    return ipv4_addr
                candidates.append((is_up, bool(ip_obj.is_private), speed, ipv4_addr))
            except ValueError:
                continue

        # 3. Offline / isolated LAN fallback: pick best active private interface
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][3]

        return fallback_gw_key

    @classmethod
    def list_interfaces(cls, include_loopback: bool = False) -> List[NetworkInterfaceInfo]:
        """List all IPv4-capable network interfaces with their MAC, CIDR, and gateway."""
        addrs_map = psutil.net_if_addrs()
        stats_map = psutil.net_if_stats()
        gateways = cls.get_default_gateways(addrs_map=addrs_map)
        primary_ip = cls.get_primary_outbound_ip(
            gateways=gateways,
            addrs_map=addrs_map,
            stats_map=stats_map,
        )

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
            if not gateway_ip and gateways.get("*"):
                try:
                    if ipaddress.IPv4Address(gateways["*"]) in network:
                        gateway_ip = gateways["*"]
                except ValueError:
                    pass

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


