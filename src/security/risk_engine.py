"""Risk scoring and threat classification engine for Network Sentry."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, PortScanRecord, SecurityAlertRecord
from src.security.port_scanner import HIGH_RISK_PORTS
from src.utils.logger import setup_logger
from src.utils.oui_lookup import OUILookup

logger = setup_logger("RiskEngine")

PORT_RISK_WEIGHTS: Dict[int, int] = {
    23: 35,    # Telnet (cleartext)
    2375: 40,  # Unencrypted Docker daemon
    445: 25,   # SMB
    21: 20,    # FTP
    3389: 20,  # RDP
    5900: 20,  # VNC
    6379: 25,  # Redis
    135: 10,   # MSRPC
    139: 10,   # NetBIOS
    1433: 15,  # MSSQL
    3306: 12,  # MySQL
    5432: 12,  # PostgreSQL
    1883: 12,  # MQTT
    554: 8,    # RTSP
    8080: 5,   # HTTP Admin/Proxy
    80: 3,     # HTTP
    22: 5,     # SSH
}


@dataclass
class RiskAssessment:
    """Detailed result of evaluating a device's security risk."""

    mac: str
    ip: str
    risk_score: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[str] = field(default_factory=list)
    alerts: List[SecurityAlertRecord] = field(default_factory=list)


class RiskEngine:
    """Computes numeric risk scores (0-100) and risk levels (LOW/MEDIUM/HIGH/CRITICAL)."""

    def __init__(self) -> None:
        self._notified_port_alerts: Set[str] = set()

    @staticmethod
    def score_to_level(score: int) -> str:
        """Map a numeric risk score (0-100) to a categorical risk level."""
        clamped = max(0, min(100, int(score)))
        if clamped >= 85:
            return "CRITICAL"
        if clamped >= 60:
            return "HIGH"
        if clamped >= 30:
            return "MEDIUM"
        return "LOW"

    def evaluate_device(
        self,
        device: DeviceRecord,
        open_ports: Optional[Sequence[PortScanRecord]] = None,
        active_alerts: Optional[Sequence[SecurityAlertRecord]] = None,
        is_new_device: bool = False,
        db: Optional[DatabaseManager] = None,
    ) -> RiskAssessment:
        """
        Calculate the security risk score and classification for a single device.
        Updates the device's risk score/level in `db` if provided.
        """
        score = 0
        reasons: List[str] = []
        new_alerts: List[SecurityAlertRecord] = []
        norm_mac = OUILookup.normalize_mac(device.mac) or device.mac.upper().strip()

        ports = list(open_ports) if open_ports is not None else []
        alerts = list(active_alerts) if active_alerts is not None else []

        # 1. Check active security alerts associated with this MAC or IP
        has_arp_spoof = False
        has_mac_flap = False
        for alert in alerts:
            if alert.is_resolved:
                continue
            if alert.mac.upper().strip() == norm_mac or alert.ip == device.ip:
                if alert.alert_type == "ARP_SPOOFING" or alert.severity == "CRITICAL":
                    has_arp_spoof = True
                elif alert.alert_type == "MAC_FLAPPING":
                    has_mac_flap = True

        if has_arp_spoof:
            score += 90
            reasons.append("Involved in ARP Spoofing / MITM anomaly (+90)")
        if has_mac_flap:
            score += 35
            reasons.append("MAC/IP flapping anomaly detected (+35)")

        # 2. Trust & Identity posture
        if not device.is_trusted:
            score += 20
            reasons.append("Untrusted device (+20)")
            if is_new_device:
                score += 10
                reasons.append("Newly discovered on network (+10)")

        # 3. Vendor / MAC Randomization check
        if OUILookup.is_randomized_mac(norm_mac) or device.vendor == "Randomized / Private MAC":
            if not device.is_trusted:
                score += 12
                reasons.append("Randomized / Locally Administered MAC (+12)")
        elif device.vendor in ("Unknown Vendor", "") and not device.is_trusted:
            score += 10
            reasons.append("Unrecognized hardware OUI vendor (+10)")

        # 4. Open TCP Ports assessment
        port_score_total = 0
        for p_rec in ports:
            if p_rec.state != "OPEN":
                continue
            p_num = p_rec.port
            weight = PORT_RISK_WEIGHTS.get(p_num, 4)
            # Trusted devices receive reduced penalty for standard administrative ports
            if device.is_trusted and p_num not in (23, 2375):
                weight = max(0, weight // 3)
            port_score_total += weight

            if p_num in HIGH_RISK_PORTS:
                risk_desc = HIGH_RISK_PORTS[p_num]
                reasons.append(f"Port {p_num}/{p_rec.service}: {risk_desc} (+{weight})")

                if not device.is_trusted:
                    alert_key = f"{norm_mac}:{p_num}"
                    if alert_key not in self._notified_port_alerts:
                        self._notified_port_alerts.add(alert_key)
                        severity = "CRITICAL" if p_num in (23, 2375) else "WARNING"
                        p_alert = SecurityAlertRecord(
                            alert_type="SUSPICIOUS_PORT",
                            severity=severity,
                            mac=norm_mac,
                            ip=device.ip,
                            description=(
                                f"High-risk port {p_num} ({p_rec.service}) open on {device.ip} "
                                f"({norm_mac}): {risk_desc}"
                            ),
                        )
                        if db is not None:
                            p_alert.id = db.record_alert(p_alert)
                        new_alerts.append(p_alert)

        if len(ports) >= 5 and not device.is_trusted:
            port_score_total += 10
            reasons.append(f"High number of open ports ({len(ports)} open) (+10)")

        score += port_score_total
        final_score = max(0, min(100, score))
        level = self.score_to_level(final_score)

        # Ensure ARP spoofing always lands in CRITICAL
        if has_arp_spoof:
            final_score = max(90, final_score)
            level = "CRITICAL"

        device.risk_score = final_score
        device.risk_level = level

        if db is not None:
            db.update_device_risk(norm_mac, level, final_score)

        return RiskAssessment(
            mac=norm_mac,
            ip=device.ip,
            risk_score=final_score,
            risk_level=level,
            reasons=reasons,
            alerts=new_alerts,
        )
