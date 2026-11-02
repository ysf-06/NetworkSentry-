"""ARP Spoofing, MITM gateway impersonation, and MAC conflict detector."""

from typing import Dict, List, Optional, Set

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, SecurityAlertRecord
from src.utils.logger import setup_logger
from src.utils.oui_lookup import OUILookup

logger = setup_logger("ARPSpoofDetector")


class ARPSpoofDetector:
    """
    Monitors ARP mappings and live ARP packets for Man-in-the-Middle (MITM)
    ARP cache poisoning, gateway impersonation, and MAC/IP conflicts.
    """

    def __init__(self, lock_gateway_mac: bool = True) -> None:
        self.lock_gateway_mac = lock_gateway_mac
        self.gateway_ip: Optional[str] = None
        self.locked_gateway_mac: Optional[str] = None
        self._ip_mac_baseline: Dict[str, str] = {}
        self._emitted_alert_keys: Set[str] = set()

    def set_gateway(self, gateway_ip: Optional[str], gateway_mac: Optional[str] = None) -> None:
        """Configure or lock the default gateway IP and its authentic MAC address."""
        if not gateway_ip:
            return
        self.gateway_ip = gateway_ip.strip()
        if gateway_mac and OUILookup.is_valid_mac(gateway_mac):
            norm_mac = OUILookup.normalize_mac(gateway_mac)
            if self.locked_gateway_mac is None or not self.lock_gateway_mac:
                self.locked_gateway_mac = norm_mac
                logger.info("Gateway %s locked to MAC %s", self.gateway_ip, self.locked_gateway_mac)

    def reset_baseline(self) -> None:
        """Clear locked gateway MAC and baseline mappings."""
        self.locked_gateway_mac = None
        self._ip_mac_baseline.clear()
        self._emitted_alert_keys.clear()

    def analyze_scan(
        self,
        ip_to_macs: Dict[str, Set[str]],
        devices: List[DeviceRecord],
        gateway_ip: Optional[str] = None,
        db: Optional[DatabaseManager] = None,
    ) -> List[SecurityAlertRecord]:
        """
        Inspect a full ARP scan's `ip_to_macs` mapping and `devices` list for:
        1. Multiple MACs claiming the same IPv4 address (ARP conflict / MITM)
        2. Default Gateway IP resolving to a different MAC than the locked gateway MAC
        3. Single non-gateway MAC claiming multiple IPv4 addresses simultaneously
        4. Non-gateway IP sharing the locked Gateway MAC (ARP poisoning indicator)
        """
        if gateway_ip:
            self.gateway_ip = gateway_ip

        alerts: List[SecurityAlertRecord] = []
        mac_to_ips: Dict[str, Set[str]] = {}

        for ip_str, mac_set in ip_to_macs.items():
            norm_macs = {OUILookup.normalize_mac(m) for m in mac_set if OUILookup.is_valid_mac(m)}
            if not norm_macs:
                continue

            for m in norm_macs:
                mac_to_ips.setdefault(m, set()).add(ip_str)

            # Check 1: Multiple MACs claiming the same IP
            if len(norm_macs) > 1:
                sorted_macs = sorted(norm_macs)
                attacker_mac = sorted_macs[-1]
                if self.gateway_ip == ip_str and self.locked_gateway_mac in norm_macs:
                    other_macs = [m for m in sorted_macs if m != self.locked_gateway_mac]
                    if other_macs:
                        attacker_mac = other_macs[0]

                alert_key = f"DUP_IP:{ip_str}:{','.join(sorted_macs)}"
                alert = SecurityAlertRecord(
                    alert_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    mac=attacker_mac,
                    ip=ip_str,
                    description=(
                        f"CRITICAL ARP Conflict: IP {ip_str} is claimed by multiple MAC addresses "
                        f"({', '.join(sorted_macs)}). Possible ARP Spoofing / MITM attack!"
                    ),
                )
                self._register_alert(alert, alert_key, alerts, db)

            # Check 2: Gateway MAC Lock-in Verification
            if self.gateway_ip and ip_str == self.gateway_ip:
                if len(norm_macs) == 1:
                    current_gw_mac = next(iter(norm_macs))
                    if self.locked_gateway_mac is None:
                        self.locked_gateway_mac = current_gw_mac
                        logger.info(
                            "Locked default gateway (%s) baseline MAC: %s",
                            self.gateway_ip,
                            self.locked_gateway_mac,
                        )
                    elif self.lock_gateway_mac and current_gw_mac != self.locked_gateway_mac:
                        alert_key = f"GW_SPOOF:{self.gateway_ip}:{self.locked_gateway_mac}->{current_gw_mac}"
                        alert = SecurityAlertRecord(
                            alert_type="ARP_SPOOFING",
                            severity="CRITICAL",
                            mac=current_gw_mac,
                            ip=self.gateway_ip,
                            description=(
                                f"CRITICAL MITM Alert: Default Gateway ({self.gateway_ip}) MAC changed "
                                f"from locked {self.locked_gateway_mac} to {current_gw_mac}!"
                            ),
                        )
                        self._register_alert(alert, alert_key, alerts, db)

            # Track baseline IP->MAC and detect sudden MAC replacement for active host
            if len(norm_macs) == 1:
                single_mac = next(iter(norm_macs))
                prev_mac = self._ip_mac_baseline.get(ip_str)
                if prev_mac and prev_mac != single_mac and ip_str != self.gateway_ip:
                    alert_key = f"MAC_FLIP:{ip_str}:{prev_mac}->{single_mac}"
                    alert = SecurityAlertRecord(
                        alert_type="MAC_FLAPPING",
                        severity="WARNING",
                        mac=single_mac,
                        ip=ip_str,
                        description=(
                            f"Host IP {ip_str} switched MAC address from {prev_mac} to {single_mac}."
                        ),
                    )
                    self._register_alert(alert, alert_key, alerts, db)
                self._ip_mac_baseline[ip_str] = single_mac

        # Check 3: Single MAC claiming multiple IPs (especially if it matches Gateway MAC!)
        for mac_addr, claimed_ips in mac_to_ips.items():
            if len(claimed_ips) > 1:
                sorted_ips = sorted(claimed_ips)
                is_gw_impersonation = (
                    self.gateway_ip is not None and self.gateway_ip in claimed_ips
                ) or (self.locked_gateway_mac is not None and mac_addr == self.locked_gateway_mac)

                suspect_ips = [ip for ip in sorted_ips if ip != self.gateway_ip]
                target_ip = suspect_ips[0] if suspect_ips else sorted_ips[0]

                if is_gw_impersonation:
                    alert_key = f"GW_CLONE:{mac_addr}:{','.join(sorted_ips)}"
                    alert = SecurityAlertRecord(
                        alert_type="ARP_SPOOFING",
                        severity="CRITICAL",
                        mac=mac_addr,
                        ip=target_ip,
                        description=(
                            f"CRITICAL ARP Poisoning: MAC {mac_addr} is responding for both "
                            f"Default Gateway and host(s): {', '.join(sorted_ips)}!"
                        ),
                    )
                    self._register_alert(alert, alert_key, alerts, db)
                else:
                    alert_key = f"MULTI_IP:{mac_addr}:{','.join(sorted_ips)}"
                    alert = SecurityAlertRecord(
                        alert_type="MAC_FLAPPING",
                        severity="WARNING",
                        mac=mac_addr,
                        ip=target_ip,
                        description=(
                            f"Single MAC {mac_addr} is associated with multiple IPs simultaneously: "
                            f"{', '.join(sorted_ips)}."
                        ),
                    )
                    self._register_alert(alert, alert_key, alerts, db)

        return alerts

    def inspect_arp_packet(
        self,
        src_mac: str,
        src_ip: str,
        dst_mac: str,
        dst_ip: str,
        opcode: int,
        is_gratuitous: bool = False,
        db: Optional[DatabaseManager] = None,
    ) -> Optional[SecurityAlertRecord]:
        """
        Analyze an individual parsed ARP packet (e.g., from Native C Engine) in real time.
        Returns a `SecurityAlertRecord` if an attack or anomaly is detected.
        """
        norm_src_mac = OUILookup.normalize_mac(src_mac)
        if not OUILookup.is_valid_mac(norm_src_mac):
            return None

        # 1. Gateway MAC spoofing check
        if self.gateway_ip and src_ip == self.gateway_ip:
            if self.locked_gateway_mac is None:
                self.locked_gateway_mac = norm_src_mac
            elif norm_src_mac != self.locked_gateway_mac:
                alert = SecurityAlertRecord(
                    alert_type="ARP_SPOOFING",
                    severity="CRITICAL",
                    mac=norm_src_mac,
                    ip=src_ip,
                    description=(
                        f"Live Packet Alert: Unauthorized MAC {norm_src_mac} sent ARP "
                        f"{'Reply' if opcode == 2 else 'Request'} claiming Gateway IP {src_ip} "
                        f"(Expected {self.locked_gateway_mac}, gratuitous={is_gratuitous})."
                    ),
                )
                if db is not None:
                    alert.id = db.record_alert(alert)
                return alert

        # 2. Gratuitous ARP Reply changing an existing baseline IP->MAC mapping
        prev_mac = self._ip_mac_baseline.get(src_ip)
        if prev_mac and prev_mac != norm_src_mac and (opcode == 2 or is_gratuitous):
            alert = SecurityAlertRecord(
                alert_type="ARP_SPOOFING",
                severity="CRITICAL" if is_gratuitous else "WARNING",
                mac=norm_src_mac,
                ip=src_ip,
                description=(
                    f"Suspicious ARP {'Gratuitous ' if is_gratuitous else ''}Packet: "
                    f"IP {src_ip} claimed by {norm_src_mac} (previously {prev_mac})."
                ),
            )
            if db is not None:
                alert.id = db.record_alert(alert)
            return alert

        self._ip_mac_baseline[src_ip] = norm_src_mac
        return None

    def _register_alert(
        self,
        alert: SecurityAlertRecord,
        alert_key: str,
        alerts_out: List[SecurityAlertRecord],
        db: Optional[DatabaseManager],
    ) -> None:
        alerts_out.append(alert)
        if db is not None and alert_key not in self._emitted_alert_keys:
            alert.id = db.record_alert(alert)
            self._emitted_alert_keys.add(alert_key)
        logger.warning("[%s] %s — %s", alert.severity, alert.alert_type, alert.description)
