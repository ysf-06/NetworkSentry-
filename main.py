"""Network Sentry — Main Entry Point & Phase 1 Diagnostic CLI."""

import argparse
import socket
import sys
from typing import Optional

from src.core.interface_detector import InterfaceDetector
from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord
from src.utils.config import ConfigManager
from src.utils.logger import setup_logger


def run_phase1_diagnostics(config_path: str = "config.json") -> int:
    """Execute Phase 1 foundation checks: Config, Interface Detection, and SQLite WAL DB."""
    cfg = ConfigManager(config_path)
    logger = setup_logger(
        "NetworkSentry",
        log_file=cfg.get("logging", "file", "networksentry.log"),
    )

    print("=" * 72)
    print("  NETWORK SENTRY — Phase 1: Project Foundation Diagnostic")
    print("=" * 72)

    # 1. Detect Network Interfaces
    interfaces = InterfaceDetector.list_interfaces(include_loopback=False)
    print(f"\n[1] Detected IPv4 Network Interfaces ({len(interfaces)} found):")
    for idx, iface in enumerate(interfaces, start=1):
        primary_tag = " [PRIMARY]" if iface.is_primary else ""
        status_tag = "UP" if iface.is_up else "DOWN"
        print(
            f"  {idx}. {iface.name}{primary_tag} ({status_tag}, {iface.speed_mbps} Mbps)\n"
            f"     IP: {iface.ip_address} | Mask: {iface.netmask} | CIDR: {iface.cidr}\n"
            f"     MAC: {iface.mac_address} | Gateway: {iface.gateway_ip or 'N/A'}"
        )

    preferred_iface: Optional[str] = cfg.get("network", "preferred_interface")
    active = InterfaceDetector.get_active_interface(preferred_name=preferred_iface)
    if active:
        logger.info(
            "Selected active interface: %s (%s on %s, Gateway: %s)",
            active.name,
            active.ip_address,
            active.cidr,
            active.gateway_ip,
        )
    else:
        logger.warning("No active non-loopback IPv4 interface detected.")

    # 2. Initialize & Verify SQLite Database
    db_path = cfg.get("database", "path", "networksentry.db")
    wal_mode = bool(cfg.get("database", "wal_mode", True))
    db = DatabaseManager(db_path=db_path, wal_mode=wal_mode)
    health = db.check_health()

    print("\n[2] SQLite Database Status:")
    print(f"  Path         : {health['db_path']}")
    print(f"  Journal Mode : {health['journal_mode'].upper()}")
    print(f"  Tables       : {', '.join(health['tables'])}")
    print(f"  Health Check : {'PASSED' if health['is_healthy'] else 'FAILED'}")

    # 3. Register Local Host in Database if active interface exists
    if active and active.mac_address != "00:00:00:00:00:00":
        local_device = DeviceRecord(
            mac=active.mac_address,
            ip=active.ip_address,
            hostname=socket.gethostname(),
            vendor="Local Host (This PC)",
            is_online=True,
            is_trusted=True,
            risk_level="LOW",
            risk_score=0,
            notes=f"Primary interface: {active.name}",
        )
        is_new, _ = db.upsert_device(local_device)
        logger.info(
            "Local host device (%s / %s) registered in SQLite (is_new=%s).",
            local_device.ip,
            local_device.mac,
            is_new,
        )

    stats = db.get_dashboard_stats()
    print("\n[3] Current Database Summary:")
    print(
        f"  Total Devices: {stats['total_devices']} | "
        f"Online: {stats['online_devices']} | "
        f"Trusted: {stats['trusted_devices']} | "
        f"Unresolved Alerts: {stats['unresolved_alerts']}"
    )
    print("=" * 72)
    return 0 if health["is_healthy"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Sentry — Local Network Discovery & Security Monitor"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)",
    )
    args = parser.parse_args()
    sys.exit(run_phase1_diagnostics(config_path=args.config))


if __name__ == "__main__":
    main()
