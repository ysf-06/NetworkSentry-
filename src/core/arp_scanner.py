"""Active ARP scanner, OS ARP cache reader, and device discovery state tracker."""

import ctypes
import ipaddress
import platform
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from src.database.db_manager import DatabaseManager
from src.database.models import (
    DeviceRecord,
    NetworkInterfaceInfo,
    ScanSessionRecord,
    SecurityAlertRecord,
)
from src.utils.logger import setup_logger
from src.utils.oui_lookup import OUILookup

logger = setup_logger("ARPScanner")


@dataclass
class DiscoveryResult:
    """Summary of a completed network discovery scan cycle."""

    session_id: int
    interface: NetworkInterfaceInfo
    discovered_devices: List[DeviceRecord] = field(default_factory=list)
    new_devices: List[DeviceRecord] = field(default_factory=list)
    ip_changed_devices: List[Tuple[DeviceRecord, str]] = field(default_factory=list)
    went_offline_count: int = 0
    alerts_created: List[SecurityAlertRecord] = field(default_factory=list)
    ip_to_macs: Dict[str, Set[str]] = field(default_factory=dict)
    duration_seconds: float = 0.0


class ARPScanner:
    """High-speed cross-platform ARP scanner and device state synchronizer."""

    def __init__(
        self,
        oui_lookup: Optional[OUILookup] = None,
        max_workers: int = 64,
        resolve_hostnames: bool = True,
        rate_limit_delay_ms: float = 0.0,
    ) -> None:
        self.oui = oui_lookup or OUILookup()
        self.max_workers = max(4, min(max_workers, 256))
        self.resolve_hostnames = resolve_hostnames
        self.rate_limit_delay_ms = max(0.0, float(rate_limit_delay_ms))
        self._is_windows = platform.system().lower() == "windows"
        self._iphlpapi = None
        if self._is_windows:
            try:
                self._iphlpapi = ctypes.windll.iphlpapi  # type: ignore[attr-defined]
            except Exception as exc:
                logger.debug("Could not load iphlpapi.dll: %s", exc)

    @staticmethod
    def get_target_hosts(cidr: str, local_ip: Optional[str] = None, max_hosts: int = 254) -> List[str]:
        """
        Calculate host IPv4 addresses to scan for a given CIDR.
        If the network is larger than /24 (e.g., /16) and `local_ip` is provided,
        scopes the scan to the /24 subnet containing `local_ip` to keep scans fast.
        """
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            return []

        if network.num_addresses > 256 and local_ip:
            try:
                network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            except ValueError:
                pass

        hosts = [str(ip) for ip in network.hosts()]
        return hosts[:max_hosts]

    @staticmethod
    def _ip_to_net_ulong(ip_str: str) -> int:
        """Convert an IPv4 string to a 32-bit unsigned integer in network byte order."""
        packed = socket.inet_aton(ip_str)
        return struct.unpack("=I", packed)[0]

    def send_arp_request(self, target_ip: str, src_ip: Optional[str] = None) -> Optional[str]:
        """
        Send a kernel-level ARP request to `target_ip` and return its normalized MAC address.
        On Windows, uses `iphlpapi.SendARP`. On Linux/POSIX, triggers a fast UDP/ICMP probe
        and inspects the kernel neighbor table.
        """
        if self.rate_limit_delay_ms > 0:
            time.sleep(self.rate_limit_delay_ms / 1000.0)
        if self._is_windows and self._iphlpapi is not None:
            try:
                dest_addr = ctypes.c_ulong(self._ip_to_net_ulong(target_ip))
                src_addr = ctypes.c_ulong(self._ip_to_net_ulong(src_ip) if src_ip else 0)
                mac_buf = (ctypes.c_ubyte * 6)()
                addr_len = ctypes.c_ulong(6)

                res = self._iphlpapi.SendARP(
                    dest_addr,
                    src_addr,
                    ctypes.byref(mac_buf),
                    ctypes.byref(addr_len),
                )
                if res == 0 and addr_len.value == 6:
                    raw_mac = ":".join(f"{b:02X}" for b in mac_buf)
                    if OUILookup.is_valid_mac(raw_mac) and raw_mac != "FF:FF:FF:FF:FF:FF":
                        return raw_mac
            except Exception:
                return None
            return None
        else:
            # POSIX fallback: trigger kernel ARP resolution via short UDP datagram
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(0.2)
                    sock.sendto(b"", (target_ip, 33434))
            except OSError:
                pass
            arp_map = self.read_os_arp_table()
            macs = arp_map.get(target_ip)
            if macs:
                return next(iter(macs))
            return None

    @classmethod
    def read_os_arp_table(cls, arp_output: Optional[str] = None) -> Dict[str, Set[str]]:
        """
        Parse the OS ARP table (`arp -a` or `/proc/net/arp`) into a mapping of
        `ip_address -> set_of_normalized_macs`.
        Excludes broadcast, multicast, and incomplete MAC addresses.
        """
        ip_to_macs: Dict[str, Set[str]] = {}

        if arp_output is None:
            arp_output = ""
            if platform.system().lower() != "windows" and Path("/proc/net/arp").exists():
                try:
                    arp_output = Path("/proc/net/arp").read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    pass

            if not arp_output:
                try:
                    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    proc = subprocess.run(
                        ["arp", "-a"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=creationflags,
                    )
                    arp_output = proc.stdout
                except Exception as exc:
                    logger.debug("Failed to read OS ARP table: %s", exc)
                    return ip_to_macs

        # Match IPv4 and MAC address on the same line
        line_pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?"
            r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})"
        )

        for line in arp_output.splitlines():
            match = line_pattern.search(line)
            if not match:
                continue
            ip_str, raw_mac = match.group(1), match.group(2)
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
                    continue
                if ip_str.endswith(".255") or ip_str == "255.255.255.255":
                    continue
            except ValueError:
                continue

            norm_mac = OUILookup.normalize_mac(raw_mac)
            if not OUILookup.is_valid_mac(norm_mac):
                continue
            if norm_mac == "FF:FF:FF:FF:FF:FF" or norm_mac.startswith("01:00:5E"):
                continue

            ip_to_macs.setdefault(ip_str, set()).add(norm_mac)

        return ip_to_macs

    @staticmethod
    def resolve_hostname(ip_address: str) -> str:
        """Attempt reverse DNS resolution for an IPv4 address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            if hostname and hostname != ip_address:
                return hostname.split(".")[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
        return "Unknown"

    def scan_subnet(
        self,
        interface: NetworkInterfaceInfo,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[List[DeviceRecord], Dict[str, Set[str]]]:
        """
        Actively scan all hosts in `interface.cidr` via concurrent ARP requests,
        merge with the OS ARP table, resolve OUI vendors and hostnames, and return
        a list of discovered `DeviceRecord` objects plus `ip_to_macs` mapping.
        """
        target_ips = self.get_target_hosts(interface.cidr, local_ip=interface.ip_address)
        ip_to_macs: Dict[str, Set[str]] = {}

        # 1. Include local host
        if OUILookup.is_valid_mac(interface.mac_address):
            norm_local = OUILookup.normalize_mac(interface.mac_address)
            ip_to_macs.setdefault(interface.ip_address, set()).add(norm_local)

        # 2. Active concurrent ARP sweep
        completed = 0

        if target_ips:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {
                    executor.submit(self.send_arp_request, ip, interface.ip_address): ip
                    for ip in target_ips
                    if ip != interface.ip_address
                }
                total = len(future_to_ip)
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    try:
                        mac = future.result()
                        if mac:
                            ip_to_macs.setdefault(ip, set()).add(mac)
                    except Exception:
                        pass
                    if progress_callback:
                        progress_callback(completed, total)

        # 3. Merge passive OS ARP cache entries within the target subnet
        try:
            subnet_net = ipaddress.IPv4Network(interface.cidr, strict=False)
        except ValueError:
            subnet_net = None

        cached_table = self.read_os_arp_table()
        for ip_str, mac_set in cached_table.items():
            if subnet_net is not None:
                try:
                    if ipaddress.IPv4Address(ip_str) not in subnet_net:
                        continue
                except ValueError:
                    continue
            ip_to_macs.setdefault(ip_str, set()).update(mac_set)

        # 4. Resolve hostnames concurrently for discovered IPs
        discovered_ips = list(ip_to_macs.keys())
        ip_to_hostname: Dict[str, str] = {}
        if self.resolve_hostnames and discovered_ips:
            with ThreadPoolExecutor(max_workers=min(32, len(discovered_ips))) as executor:
                hn_futures = {
                    executor.submit(self.resolve_hostname, ip): ip
                    for ip in discovered_ips
                    if ip != interface.ip_address
                }
                for hn_fut in as_completed(hn_futures):
                    ip = hn_futures[hn_fut]
                    try:
                        ip_to_hostname[ip] = hn_fut.result()
                    except Exception:
                        ip_to_hostname[ip] = "Unknown"

        ip_to_hostname[interface.ip_address] = socket.gethostname()

        # 5. Build DeviceRecord list (deduplicated by MAC, preferring most recent IP)
        now = datetime.now().isoformat(timespec="seconds")
        mac_to_device: Dict[str, DeviceRecord] = {}

        # Sort IPs numerically so deterministic order is preserved
        sorted_ips = sorted(discovered_ips, key=lambda x: tuple(int(p) for p in x.split(".")))
        for ip_str in sorted_ips:
            for mac in sorted(ip_to_macs[ip_str]):
                vendor = self.oui.lookup(mac)
                hostname = ip_to_hostname.get(ip_str, "Unknown")
                is_local = ip_str == interface.ip_address and mac == OUILookup.normalize_mac(interface.mac_address)
                is_gateway = interface.gateway_ip is not None and ip_str == interface.gateway_ip

                if is_local and vendor == "Unknown Vendor":
                    vendor = "Local Host (This PC)"
                if is_gateway and hostname == "Unknown":
                    hostname = "Default-Gateway"

                notes = ""
                if is_local:
                    notes = f"Local Host ({interface.name})"
                elif is_gateway:
                    notes = "Default Gateway / Router"

                mac_to_device[mac] = DeviceRecord(
                    mac=mac,
                    ip=ip_str,
                    hostname=hostname,
                    vendor=vendor,
                    first_seen=now,
                    last_seen=now,
                    is_online=True,
                    is_trusted=is_local or is_gateway,
                    risk_level="LOW",
                    risk_score=0,
                    notes=notes,
                )

        devices = list(mac_to_device.values())
        return devices, ip_to_macs

    def scan_and_sync(
        self,
        interface: NetworkInterfaceInfo,
        db: DatabaseManager,
        alert_on_new_device: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> DiscoveryResult:
        """
        Execute a full subnet ARP discovery scan and synchronize results with SQLite:
        - Upserts discovered devices and tracks IP changes
        - Generates NEW_DEVICE alerts for previously unseen untrusted devices
        - Marks absent devices as offline
        - Records a ScanSessionRecord
        """
        start_time = datetime.now()
        session_id = db.create_scan_session(
            ScanSessionRecord(
                interface_name=interface.name,
                subnet_cidr=interface.cidr,
                gateway_ip=interface.gateway_ip,
                started_at=start_time.isoformat(timespec="seconds"),
            )
        )

        devices, ip_to_macs = self.scan_subnet(interface, progress_callback=progress_callback)

        new_devices: List[DeviceRecord] = []
        ip_changed_devices: List[Tuple[DeviceRecord, str]] = []
        alerts_created: List[SecurityAlertRecord] = []
        active_macs: List[str] = []

        for dev in devices:
            active_macs.append(dev.mac)
            is_new, prev_ip = db.upsert_device(dev)

            if is_new:
                new_devices.append(dev)
                if alert_on_new_device and not dev.is_trusted:
                    alert = SecurityAlertRecord(
                        alert_type="NEW_DEVICE",
                        severity="WARNING",
                        mac=dev.mac,
                        ip=dev.ip,
                        description=(
                            f"New device joined the network: {dev.ip} ({dev.mac}) "
                            f"[{dev.vendor}, Host: {dev.hostname}]"
                        ),
                    )
                    alert.id = db.record_alert(alert)
                    alerts_created.append(alert)
            elif prev_ip is not None:
                ip_changed_devices.append((dev, prev_ip))

        offline_count = db.mark_offline_devices(active_macs)
        db.finish_scan_session(
            session_id=session_id,
            devices_found=len(devices),
            new_devices=len(new_devices),
            alerts_triggered=len(alerts_created),
        )

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(
            "Scan session #%d completed in %.2fs: %d online, %d new, %d offline, %d alerts.",
            session_id,
            duration,
            len(devices),
            len(new_devices),
            offline_count,
            len(alerts_created),
        )

        # Refresh device records from DB so preserved fields (trust, notes, risk) are up-to-date
        synced_devices = [db.get_device_by_mac(d.mac) or d for d in devices]

        return DiscoveryResult(
            session_id=session_id,
            interface=interface,
            discovered_devices=synced_devices,
            new_devices=new_devices,
            ip_changed_devices=ip_changed_devices,
            went_offline_count=offline_count,
            alerts_created=alerts_created,
            ip_to_macs=ip_to_macs,
            duration_seconds=duration,
        )
