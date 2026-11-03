"""Data models for Network Sentry."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class NetworkInterfaceInfo:
    """Represents a local network interface card (NIC) and its IPv4 configuration."""

    name: str
    ip_address: str
    netmask: str
    mac_address: str
    cidr: str
    gateway_ip: Optional[str] = None
    is_up: bool = True
    is_primary: bool = False
    speed_mbps: int = 0
    mtu: int = 1500


@dataclass
class DeviceRecord:
    """Represents a discovered device on the local network."""

    mac: str
    ip: str
    hostname: str = "Unknown"
    vendor: str = "Unknown Vendor"
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    is_online: bool = True
    is_trusted: bool = False
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int = 0
    notes: str = ""


@dataclass
class SecurityAlertRecord:
    """Represents a security anomaly or intrusion alert."""

    alert_type: str  # NEW_DEVICE, ARP_SPOOFING, SUSPICIOUS_PORT, MAC_FLAPPING
    severity: str    # INFO, WARNING, CRITICAL
    mac: str
    ip: str
    description: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    is_resolved: bool = False
    confidence: str = "HIGH_CONFIDENCE"  # HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, SUSPECTED_DHCP_OR_REBOOT
    first_seen: Optional[str] = None
    last_changed: Optional[str] = None
    is_acknowledged: bool = False
    acknowledgement_notes: str = ""
    id: Optional[int] = None



@dataclass
class PortScanRecord:
    """Represents an open TCP port discovered on a device."""

    mac: str
    ip: str
    port: int
    protocol: str = "TCP"
    service: str = "unknown"
    banner: str = ""
    state: str = "OPEN"
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: Optional[int] = None


@dataclass
class ScanSessionRecord:
    """Represents a single network discovery scan session."""

    interface_name: str
    subnet_cidr: str
    gateway_ip: Optional[str]
    devices_found: int = 0
    new_devices: int = 0
    alerts_triggered: int = 0
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: Optional[str] = None
    id: Optional[int] = None


@dataclass
class DeviceHistoryRecord:
    """Represents a historical state transition event for a device."""

    mac: str
    ip: str
    event_type: str  # FIRST_SEEN, IP_CHANGED, RECONNECTED, OFFLINE
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    details: str = ""
    id: Optional[int] = None


