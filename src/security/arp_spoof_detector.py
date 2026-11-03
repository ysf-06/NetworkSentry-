from datetime import datetime
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
    Distinguishes true attacks from common DHCP churn, mesh roaming, and router reboots.
    """

    def __init__(self, lock_gateway_mac: bool = True) -> None:
        self.lock_gateway_mac = lock_gateway_mac
        self.gateway_ip: Optional[str] = None
        self.locked_gateway_mac: Optional[str] = None
        self._ip_mac_baseline: Dict[str, str] = {}
        self._ip_mac_first_seen: Dict[str, str] = {}
        self._ip_mac_last_changed: Dict[str, str] = {}
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
        self._ip_mac_first_seen.clear()
        self._ip_mac_last_changed.clear()
        self._emitted_alert_keys.clear()

    def approve_expected_change(
        self,
        ip: str,
        new_mac: str,
        db: Optional[DatabaseManager] = None,
        notes: str = "User approved expected network hardware or DHCP change",
    ) -> bool:
        """
        Mark a detected MAC transition for `ip` as an approved, expected network event.
        Updates locked gateway MAC baseline if applicable, resolves existing alerts,
        and re-evaluates risk.
        """
        norm_mac = OUILookup.normalize_mac(new_mac)
        clean_ip = ip.strip()

        if self.gateway_ip and clean_ip == self.gateway_ip:
            self.locked_gateway_mac = norm_mac
            logger.info("Updated locked default gateway %s to approved MAC %s", clean_ip, norm_mac)

        self._ip_mac_baseline[clean_ip] = norm_mac
        self._ip_mac_last_changed[clean_ip] = datetime.now().isoformat(timespec="seconds")

        if db is not None:
            active_alerts = db.get_alerts(unresolved_only=True)
            for a in active_alerts:
                if a.ip == clean_ip or a.mac == norm_mac:
                    if a.id is not None:
                        db.acknowledge_alert(a.id, notes=notes, mark_resolved=True)

            device = db.get_device_by_mac(norm_mac)
            if device:
                device.is_trusted = True
                db.upsert_device(device)
                from src.security.risk_engine import RiskEngine

                RiskEngine().evaluate_device(device, db=db)

        return True

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
        now = datetime.now().isoformat(timespec="seconds")

        for ip_str, mac_set in ip_to_macs.items():
            norm_macs = {OUILookup.normalize_mac(m) for m in mac_set if OUILookup.is_valid_mac(m)}
            if not norm_macs:
                continue

            self._ip_mac_first_seen.setdefault(ip_str, now)

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
                    confidence="HIGH_CONFIDENCE",
                    first_seen=self._ip_mac_first_seen.get(ip_str, now),
                    last_changed=now,
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
                        same_vendor = OUILookup.extract_oui(self.locked_gateway_mac) == OUILookup.extract_oui(current_gw_mac)
                        confidence = "SUSPECTED_DHCP_OR_REBOOT" if same_vendor else "MEDIUM_CONFIDENCE"
                        vendor_note = " (Same manufacturer OUI: likely router reboot or multi-band Wi-Fi/mesh AP handover)" if same_vendor else ""

                        alert = SecurityAlertRecord(
                            alert_type="ARP_SPOOFING",
                            severity="CRITICAL",
                            mac=current_gw_mac,
                            ip=self.gateway_ip,
                            description=(
                                f"CRITICAL MITM Alert: Default Gateway ({self.gateway_ip}) MAC changed "
                                f"from locked {self.locked_gateway_mac} to {current_gw_mac}!{vendor_note}"
                            ),
                            confidence=confidence,
                            first_seen=self._ip_mac_first_seen.get(ip_str, now),
                            last_changed=now,
                        )
                        self._register_alert(alert, alert_key, alerts, db)

            # Track baseline IP->MAC and detect sudden MAC replacement for active host
            if len(norm_macs) == 1:
                single_mac = next(iter(norm_macs))
                prev_mac = self._ip_mac_baseline.get(ip_str)
                if prev_mac and prev_mac != single_mac and ip_str != self.gateway_ip:
                    alert_key = f"MAC_FLIP:{ip_str}:{prev_mac}->{single_mac}"
                    is_rand = OUILookup.is_locally_administered(single_mac)
                    same_oui = OUILookup.extract_oui(prev_mac) == OUILookup.extract_oui(single_mac)
                    confidence = "SUSPECTED_DHCP_OR_REBOOT" if (is_rand or same_oui) else "MEDIUM_CONFIDENCE"
                    hint = " (Likely DHCP lease expiration, device reboot, or private Wi-Fi MAC rotation)" if (is_rand or same_oui) else ""

                    alert = SecurityAlertRecord(
                        alert_type="MAC_FLAPPING",
                        severity="WARNING",
                        mac=single_mac,
                        ip=ip_str,
                        description=(
                            f"Host IP {ip_str} switched MAC address from {prev_mac} to {single_mac}.{hint}"
                        ),
                        confidence=confidence,
                        first_seen=self._ip_mac_first_seen.get(ip_str, now),
                        last_changed=now,
                    )
                    self._register_alert(alert, alert_key, alerts, db)
                self._ip_mac_baseline[ip_str] = single_mac
                self._ip_mac_last_changed[ip_str] = now

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
                        confidence="HIGH_CONFIDENCE",
                        first_seen=self._ip_mac_first_seen.get(target_ip, now),
                        last_changed=now,
                    )
                    self._register_alert(alert, alert_key, alerts, db)
                else:
                    alert_key = f"MULTI_IP:{mac_addr}:{','.join(sorted_ips)}"
                    is_rand = OUILookup.is_locally_administered(mac_addr)
                    confidence = "SUSPECTED_DHCP_OR_REBOOT" if is_rand else "MEDIUM_CONFIDENCE"
                    alert = SecurityAlertRecord(
                        alert_type="MAC_FLAPPING",
                        severity="WARNING",
                        mac=mac_addr,
                        ip=target_ip,
                        description=(
                            f"Single MAC {mac_addr} is associated with multiple IPs simultaneously: "
                            f"{', '.join(sorted_ips)}."
                        ),
                        confidence=confidence,
                        first_seen=self._ip_mac_first_seen.get(target_ip, now),
                        last_changed=now,
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
        eth_src_mac: Optional[str] = None,
        mac_mismatch: bool = False,
        db: Optional[DatabaseManager] = None,
    ) -> Optional[SecurityAlertRecord]:
        """
        Analyze an individual parsed ARP packet (e.g., from Native C Engine) in real time.
        Returns a `SecurityAlertRecord` if an attack or anomaly is detected.
        """
        norm_src_mac = OUILookup.normalize_mac(src_mac)
        if not OUILookup.is_valid_mac(norm_src_mac):
            return None

        norm_eth_src = OUILookup.normalize_mac(eth_src_mac) if eth_src_mac else ""
        has_header_mismatch = bool(mac_mismatch) or (
            bool(norm_eth_src) and OUILookup.is_valid_mac(norm_eth_src) and norm_eth_src != norm_src_mac
        )

        now = datetime.now().isoformat(timespec="seconds")
        # 0. Ethernet frame source MAC != ARP Sender Hardware Address (L2/L3 header forgery)
        if has_header_mismatch:
            culprit_mac = norm_eth_src if OUILookup.is_valid_mac(norm_eth_src) else norm_src_mac
            alert = SecurityAlertRecord(
                alert_type="ARP_SPOOFING",
                severity="CRITICAL",
                mac=culprit_mac,
                ip=src_ip,
                description=(
                    f"Live Packet Alert: Ethernet/ARP MAC Mismatch! Frame sent by physical MAC "
                    f"{culprit_mac} but forged ARP Sender MAC {norm_src_mac} for IP {src_ip}."
                ),
                confidence="HIGH_CONFIDENCE",
                first_seen=self._ip_mac_first_seen.get(src_ip, now),
                last_changed=now,
            )
            if db is not None:
                alert.id = db.record_alert(alert)
            return alert

        # 1. Gateway MAC spoofing check
        if self.gateway_ip and src_ip == self.gateway_ip:
            if self.locked_gateway_mac is None or not self.lock_gateway_mac:
                self.locked_gateway_mac = norm_src_mac
            elif norm_src_mac != self.locked_gateway_mac:
                same_vendor = OUILookup.extract_oui(self.locked_gateway_mac) == OUILookup.extract_oui(norm_src_mac)
                conf = "SUSPECTED_DHCP_OR_REBOOT" if same_vendor else "HIGH_CONFIDENCE"
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
                    confidence=conf,
                    first_seen=self._ip_mac_first_seen.get(src_ip, now),
                    last_changed=now,
                )
                if db is not None:
                    alert.id = db.record_alert(alert)
                return alert

        # 2. Gratuitous ARP Reply changing an existing baseline IP->MAC mapping
        prev_mac = self._ip_mac_baseline.get(src_ip)
        if prev_mac and prev_mac != norm_src_mac and (opcode == 2 or is_gratuitous):
            same_vendor = OUILookup.extract_oui(prev_mac) == OUILookup.extract_oui(norm_src_mac)
            conf = "SUSPECTED_DHCP_OR_REBOOT" if same_vendor else ("HIGH_CONFIDENCE" if is_gratuitous else "MEDIUM_CONFIDENCE")
            alert = SecurityAlertRecord(
                alert_type="ARP_SPOOFING",
                severity="CRITICAL" if is_gratuitous else "WARNING",
                mac=norm_src_mac,
                ip=src_ip,
                description=(
                    f"Suspicious ARP {'Gratuitous ' if is_gratuitous else ''}Packet: "
                    f"IP {src_ip} claimed by {norm_src_mac} (previously {prev_mac})."
                ),
                confidence=conf,
                first_seen=self._ip_mac_first_seen.get(src_ip, now),
                last_changed=now,
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
