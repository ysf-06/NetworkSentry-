"""CSV and JSON security audit report exporter for Network Sentry."""

import csv
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from src.database.db_manager import DatabaseManager
from src.database.models import DeviceRecord, NetworkInterfaceInfo, SecurityAlertRecord


class ReportExporter:
    """Generates CSV and JSON audit reports of discovered devices, ports, and security alerts."""

    @staticmethod
    def export_devices_csv(devices: Sequence[DeviceRecord], output_path: str | Path) -> Path:
        """Export a list of `DeviceRecord` objects to a UTF-8 CSV file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "mac",
            "ip",
            "hostname",
            "vendor",
            "is_online",
            "is_trusted",
            "risk_level",
            "risk_score",
            "first_seen",
            "last_seen",
            "notes",
        ]

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for dev in devices:
                row = asdict(dev)
                writer.writerow({k: row.get(k, "") for k in fieldnames})

        return path

    @staticmethod
    def export_alerts_csv(alerts: Sequence[SecurityAlertRecord], output_path: str | Path) -> Path:
        """Export a list of `SecurityAlertRecord` objects to a UTF-8 CSV file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "id",
            "timestamp",
            "severity",
            "alert_type",
            "ip",
            "mac",
            "description",
            "is_resolved",
        ]

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                row = asdict(alert)
                writer.writerow({k: row.get(k, "") for k in fieldnames})

        return path

    @staticmethod
    def export_full_report_json(
        db: DatabaseManager,
        output_path: str | Path,
        interface: Optional[NetworkInterfaceInfo] = None,
    ) -> Path:
        """
        Export a comprehensive JSON audit report including dashboard statistics,
        network interface metadata, devices with their open ports, security alerts,
        and recent state history.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        devices = db.get_all_devices(online_only=False)
        device_entries = []
        for dev in devices:
            dev_dict = asdict(dev)
            dev_dict["open_ports"] = [asdict(p) for p in db.get_device_ports(dev.mac)]
            device_entries.append(dev_dict)

        report_payload: Dict[str, Any] = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "generator": "Network Sentry v1.0.0",
            },
            "network_interface": asdict(interface) if interface else None,
            "summary_statistics": db.get_dashboard_stats(),
            "devices": device_entries,
            "security_alerts": [asdict(a) for a in db.get_alerts(limit=500)],
            "recent_history": [asdict(h) for h in db.get_device_history(limit=250)],
        }

        path.write_text(
            json.dumps(report_payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path
