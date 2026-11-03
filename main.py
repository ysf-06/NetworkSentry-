"""Network Sentry — Main Entry Point (PySide6 Desktop GUI & CLI Modes)."""

import argparse
import os
import socket
import sys
from pathlib import Path
from typing import Optional


def _prepare_working_directory(config_path: str = "config.json") -> None:
    """
    Normalize the process working directory before logger or database setup so
    standalone `.exe` launches from `WindowsApps`, `System32`, or arbitrary folders never fail.
    """
    from src.utils.logger import get_app_data_dir

    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if not Path(config_path).is_absolute() and not Path(config_path).exists():
            try:
                os.chdir(exe_dir)
            except OSError:
                try:
                    os.chdir(get_app_data_dir())
                except OSError:
                    pass
    else:
        cwd_str = str(Path.cwd()).lower()
        if "windowsapps" in cwd_str or "system32" in cwd_str:
            project_dir = Path(__file__).resolve().parent
            try:
                os.chdir(project_dir)
            except OSError:
                try:
                    os.chdir(get_app_data_dir())
                except OSError:
                    pass


_prepare_working_directory()

from src._version import __version__
from src.core.arp_scanner import ARPScanner
from src.core.interface_detector import InterfaceDetector
from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord
from src.native.c_bridge import NativePacketEngine
from src.security.arp_spoof_detector import ARPSpoofDetector
from src.security.port_scanner import PortScanner
from src.security.risk_engine import RiskEngine
from src.utils.config import ConfigManager
from src.utils.logger import get_app_data_dir, setup_logger
from src.utils.oui_lookup import OUILookup
from src.utils.reporter import ReportExporter


def run_diagnostics(config_path: str = "config.json") -> int:
    """Execute system diagnostics: Interface Detection, SQLite WAL DB, OUI DB, and Native C Engine."""
    _prepare_working_directory(config_path)
    cfg = ConfigManager(config_path)
    logger = setup_logger(
        "NetworkSentry",
        log_file=cfg.get("logging", "file", "networksentry.log"),
    )

    print("=" * 74)
    print(f"  NETWORK SENTRY v{__version__} — System & Security Engine Diagnostics")
    print("=" * 74)

    print(f"  App Data Dir : {get_app_data_dir()}")

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

    # 3. OUI Database & Native C Packet Engine
    oui = OUILookup()
    c_engine = NativePacketEngine(auto_compile=True)
    print("\n[3] Discovery & Native C Engine Status:")
    print(f"  OUI Database : {oui.count} vendor prefixes loaded")
    print(f"  C Engine     : {'ACTIVE' if c_engine.is_native_loaded else 'FALLBACK'} ({c_engine.version()})")
    print(f"  Npcap/libpcap: {'AVAILABLE' if c_engine.is_pcap_available() else 'NOT DETECTED (SendARP Active)'}")

    # 4. Register Local Host in Database if active interface exists
    if active and active.mac_address != "00:00:00:00:00:00":
        local_device = DeviceRecord(
            mac=active.mac_address,
            ip=active.ip_address,
            hostname=socket.gethostname(),
            vendor=oui.lookup(active.mac_address)
            if oui.lookup(active.mac_address) != "Unknown Vendor"
            else "Local Host (This PC)",
            is_online=True,
            is_trusted=True,
            risk_level="LOW",
            risk_score=0,
            notes=f"Primary interface: {active.name}",
        )
        db.upsert_device(local_device)

    stats = db.get_dashboard_stats()
    print("\n[4] Current Database Summary:")
    print(
        f"  Total Devices: {stats['total_devices']} | "
        f"Online: {stats['online_devices']} | "
        f"Trusted: {stats['trusted_devices']} | "
        f"Unresolved Alerts: {stats['unresolved_alerts']}"
    )
    print("=" * 74)
    return 0 if health["is_healthy"] else 1


def run_cli_scan(
    config_path: str = "config.json",
    export_csv: Optional[str] = None,
    export_json: Optional[str] = None,
) -> int:
    """Execute a full CLI network discovery & security scan."""
    _prepare_working_directory(config_path)
    cfg = ConfigManager(config_path)
    setup_logger("NetworkSentry", log_file=cfg.get("logging", "file", "networksentry.log"))
    db = DatabaseManager(
        db_path=cfg.get("database", "path", "networksentry.db"),
        wal_mode=bool(cfg.get("database", "wal_mode", True)),
    )
    active = InterfaceDetector.get_active_interface(cfg.get("network", "preferred_interface"))
    if not active:
        print("[Error] No active IPv4 network interface detected.")
        return 1

    if not bool(cfg.get("security", "authorized_network_consent", False)):
        print("\n[!] NOTICE: Authorized Networks Only")
        print("    You must only scan networks and devices you own or have explicit authorization to assess.")
        print("    Set 'authorized_network_consent': true in config.json to confirm authorization.\n")

    print(f"[*] Scanning subnet {active.cidr} on interface '{active.name}' (GW: {active.gateway_ip})...")
    max_workers = int(cfg.get("network", "max_workers", 24))
    rate_limit_pps = int(cfg.get("network", "rate_limit_pps", 100))
    delay_ms = 1000.0 / float(rate_limit_pps) if rate_limit_pps > 0 else 0.0

    scanner = ARPScanner(max_workers=max_workers, rate_limit_delay_ms=delay_ms)
    spoof_detector = ARPSpoofDetector(lock_gateway_mac=bool(cfg.get("security", "lock_gateway_mac", True)))
    port_scanner = PortScanner(timeout=0.35, max_workers=max_workers, rate_limit_delay_ms=delay_ms)
    risk_engine = RiskEngine()

    result = scanner.scan_and_sync(
        interface=active,
        db=db,
        alert_on_new_device=bool(cfg.get("security", "alert_on_new_device", True)),
    )
    spoof_detector.analyze_scan(
        ip_to_macs=result.ip_to_macs,
        devices=result.discovered_devices,
        gateway_ip=active.gateway_ip,
        db=db,
    )

    common_ports = cfg.get("network", "common_ports", [21, 22, 23, 80, 443, 445, 3389, 8080])
    unresolved = db.get_alerts(unresolved_only=True)
    for dev in result.discovered_devices:
        ports = port_scanner.scan_host(dev.ip, mac=dev.mac, ports=common_ports, db=db)
        risk_engine.evaluate_device(dev, open_ports=ports, active_alerts=unresolved, db=db)

    devices = db.get_all_devices(online_only=True)
    print(f"\n[+] Discovered {len(devices)} Online Device(s) in {result.duration_seconds:.2f}s:")
    print("-" * 92)
    print(f"{'IP Address':<16} {'MAC Address':<19} {'Risk':<14} {'Hostname':<18} {'Vendor'}")
    print("-" * 92)
    for d in devices:
        risk_str = f"{d.risk_level} ({d.risk_score})"
        print(f"{d.ip:<16} {d.mac:<19} {risk_str:<14} {d.hostname[:17]:<18} {d.vendor}")
    print("-" * 92)

    if export_csv:
        out_csv = ReportExporter.export_devices_csv(db.get_all_devices(), export_csv)
        print(f"[+] Exported CSV report to: {out_csv}")
    if export_json:
        out_json = ReportExporter.export_full_report_json(db, export_json, interface=active)
        print(f"[+] Exported JSON report to: {out_json}")

    return 0


def run_gui(config_path: str = "config.json") -> int:
    """Launch the PySide6 Desktop Application."""
    import ctypes

    from PySide6.QtWidgets import QApplication

    from src.gui.main_window import MainWindow
    from src.gui.widgets.cyber_charts import create_cyber_guardian_icon

    _prepare_working_directory(config_path)

    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "CyberGuardian.NetworkSentry.Desktop.1"
            )
        except Exception:
            pass

    cfg = ConfigManager(config_path)
    setup_logger("NetworkSentry", log_file=cfg.get("logging", "file", "networksentry.log"))

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Cyber Guardian — Network Sentry")
    app.setOrganizationName("CyberGuardian")
    app.setWindowIcon(create_cyber_guardian_icon(64))

    window = MainWindow(config=cfg)
    window.show()
    return app.exec()


def _ensure_cli_console() -> None:
    """Attach to parent console on Windows if running CLI flags from a --windowed executable."""
    if sys.platform == "win32" and sys.stdout is None:
        try:
            import ctypes

            if ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cyber Guardian (Network Sentry) — Local Network Discovery, C Packet Engine & Security Monitor"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file (default: config.json)",
    )
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Run system, database, and Native C Engine diagnostics and exit",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run a single CLI network discovery and security scan and exit",
    )
    parser.add_argument(
        "--test-localhost",
        action="store_true",
        help="Run ephemeral localhost port scanner verification test and exit",
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Reset and purge database to a clean starting state with only the local PC adapter",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--export-csv",
        default=None,
        help="Export device list to CSV path (used with --scan)",
    )
    parser.add_argument(
        "--export-json",
        default=None,
        help="Export full security audit report to JSON path (used with --scan)",
    )
    args = parser.parse_args()

    if args.reset_db:
        _ensure_cli_console()
        _prepare_working_directory(args.config)
        cfg = ConfigManager(args.config)
        db_path = cfg.get("database", "path", "networksentry.db")
        db = DatabaseManager(db_path=db_path)
        print("=" * 74)
        print(f"  NETWORK SENTRY v{__version__} — Database Reset to Clean Starting State")
        print("=" * 74)
        print(f"  Target Database: {db.db_path}")
        res = db.clear_all_data()
        print(f"  Purged: {res.get('devices', 0)} devices, {res.get('security_alerts', 0)} alerts, {res.get('port_scans', 0)} port scans.")

        active = InterfaceDetector.get_active_interface(cfg.get("network", "preferred_interface"))
        if active and active.mac_address and active.mac_address != "00:00:00:00:00:00":
            oui = OUILookup()
            vendor = oui.lookup(active.mac_address)
            if vendor == "Unknown Vendor":
                vendor = "Local Host (This PC)"
            db.upsert_device(
                DeviceRecord(
                    mac=active.mac_address,
                    ip=active.ip_address,
                    hostname=socket.gethostname(),
                    vendor=vendor,
                    is_online=True,
                    is_trusted=True,
                    risk_level="LOW",
                    risk_score=0,
                    notes=f"Primary interface: {active.name}",
                )
            )
            print(f"  Seeded Clean Local Host: {active.ip_address} ({active.mac_address}) [{vendor}]")
        print("  Database is now completely clean.")
        print("=" * 74)
        sys.exit(0)

    if args.test_localhost:
        _ensure_cli_console()
        print("=" * 74)
        print(f"  NETWORK SENTRY v{__version__} — Localhost Port Verification Test")
        print("=" * 74)
        res = PortScanner.run_localhost_verification()
        print("  Target IP              : 127.0.0.1")
        print(f"  Ephemeral Open Port    : {res['open_port']} (Detected: {res['detected']}, Elapsed: {res.get('elapsed_ms', 0)} ms)")
        print(f"  Ephemeral Closed Port  : {res['closed_port']} (Negative Check: {res['negative_check_passed']})")
        if res.get("record"):
            print(f"  Banner Grabbed         : '{res['record'].banner}'")
        if res.get("sandbox_restricted"):
            print(f"  Sandbox Restriction    : WSAEACCES 10013 (OS/Sandbox policy restricts local loopback socket binding)")
            print(f"  Diagnostic Context     : {res.get('message')}")
            print(f"  Verification Result    : RESTRICTED (Sandbox Policy)")
            print("=" * 74)
            sys.exit(0)
        print(f"  Verification Result    : {'PASSED' if res['success'] else 'FAILED'}")
        print("=" * 74)
        sys.exit(0 if res["success"] else 1)

    if args.diagnostics:
        _ensure_cli_console()
        sys.exit(run_diagnostics(config_path=args.config))

    if args.scan:
        _ensure_cli_console()
        sys.exit(
            run_cli_scan(
                config_path=args.config,
                export_csv=args.export_csv,
                export_json=args.export_json,
            )
        )
    sys.exit(run_gui(config_path=args.config))


if __name__ == "__main__":
    main()

