"""Thread-safe SQLite database manager for Network Sentry."""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.database.models import (
    DeviceHistoryRecord,
    DeviceRecord,
    PortScanRecord,
    ScanSessionRecord,
    SecurityAlertRecord,
)
from src.utils.logger import resolve_data_path, setup_logger

logger = setup_logger("DatabaseManager")

SCHEMA_VERSION = 2


class DatabaseManager:
    """Manages SQLite database connections, schema migrations, and queries."""

    def __init__(self, db_path: str | Path = "networksentry.db", wal_mode: bool = True) -> None:
        raw_path = Path(db_path)
        self.db_path = raw_path if raw_path.is_absolute() else resolve_data_path(raw_path, seed_from_bundle=True)
        self.wal_mode = wal_mode
        self._lock = threading.RLock()
        self.initialize_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a configured SQLite connection with row factory."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if self.wal_mode:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def initialize_schema(self) -> None:
        """Create all required tables, indexes, and apply versioned migrations."""
        with self._lock, self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    hostname TEXT DEFAULT 'Unknown',
                    vendor TEXT DEFAULT 'Unknown Vendor',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_online INTEGER DEFAULT 1,
                    is_trusted INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'LOW',
                    risk_score INTEGER DEFAULT 0,
                    notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    description TEXT NOT NULL,
                    is_resolved INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    confidence TEXT DEFAULT 'HIGH_CONFIDENCE',
                    first_seen TEXT,
                    last_changed TEXT,
                    is_acknowledged INTEGER DEFAULT 0,
                    acknowledgement_notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'TCP',
                    service TEXT DEFAULT 'unknown',
                    banner TEXT DEFAULT '',
                    state TEXT DEFAULT 'OPEN',
                    scanned_at TEXT NOT NULL,
                    UNIQUE(mac, port, protocol),
                    FOREIGN KEY (mac) REFERENCES devices(mac) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    interface_name TEXT NOT NULL,
                    subnet_cidr TEXT NOT NULL,
                    gateway_ip TEXT,
                    devices_found INTEGER DEFAULT 0,
                    new_devices INTEGER DEFAULT 0,
                    alerts_triggered INTEGER DEFAULT 0,
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
                CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(is_online);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_history_mac ON device_history(mac);
                """
            )

            # Apply incremental schema column migrations for pre-existing databases
            existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(security_alerts);").fetchall()}
            if "confidence" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN confidence TEXT DEFAULT 'HIGH_CONFIDENCE';")
            if "first_seen" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN first_seen TEXT;")
            if "last_changed" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN last_changed TEXT;")
            if "is_acknowledged" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN is_acknowledged INTEGER DEFAULT 0;")
            if "acknowledgement_notes" not in existing_cols:
                conn.execute("ALTER TABLE security_alerts ADD COLUMN acknowledgement_notes TEXT DEFAULT '';")

            now_iso = datetime.now().isoformat(timespec="seconds")
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at, description) VALUES (1, ?, 'Initial baseline tables')",
                (now_iso,),
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at, description) VALUES (2, ?, 'Add confidence and acknowledgement fields to security_alerts')",
                (now_iso,),
            )


    def check_health(self) -> Dict[str, Any]:
        """Verify database connection, WAL mode status, and table counts."""
        with self._lock, self._get_connection() as conn:
            journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
            ]
            return {
                "db_path": str(self.db_path.resolve()),
                "journal_mode": journal_mode,
                "tables": tables,
                "is_healthy": len(tables) >= 5,
            }

    def upsert_device(self, device: DeviceRecord) -> Tuple[bool, Optional[str]]:
        """
        Insert a new device or update an existing one.
        Returns (is_new_device, previous_ip_if_changed).
        """
        norm_mac = device.mac.upper().strip()
        now = datetime.now().isoformat(timespec="seconds")

        with self._lock, self._get_connection() as conn:
            existing = conn.execute(
                "SELECT ip, hostname, vendor, is_online FROM devices WHERE mac = ?",
                (norm_mac,),
            ).fetchone()

            if existing is None:
                conn.execute(
                    """
                    INSERT INTO devices (
                        mac, ip, hostname, vendor, first_seen, last_seen,
                        is_online, is_trusted, risk_level, risk_score, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        norm_mac,
                        device.ip,
                        device.hostname,
                        device.vendor,
                        device.first_seen or now,
                        device.last_seen or now,
                        1 if device.is_online else 0,
                        1 if device.is_trusted else 0,
                        device.risk_level,
                        device.risk_score,
                        device.notes,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO device_history (mac, ip, event_type, timestamp, details)
                    VALUES (?, ?, 'FIRST_SEEN', ?, ?)
                    """,
                    (norm_mac, device.ip, now, f"Vendor: {device.vendor}"),
                )
                return True, None

            prev_ip = existing["ip"]
            ip_changed = prev_ip != device.ip
            hostname = device.hostname if device.hostname != "Unknown" else existing["hostname"]
            vendor = device.vendor if device.vendor != "Unknown Vendor" else existing["vendor"]

            conn.execute(
                """
                UPDATE devices
                SET ip = ?,
                    hostname = ?,
                    vendor = ?,
                    last_seen = ?,
                    is_online = 1
                WHERE mac = ?
                """,
                (device.ip, hostname, vendor, now, norm_mac),
            )

            if ip_changed:
                conn.execute(
                    """
                    INSERT INTO device_history (mac, ip, event_type, timestamp, details)
                    VALUES (?, ?, 'IP_CHANGED', ?, ?)
                    """,
                    (norm_mac, device.ip, now, f"Changed from {prev_ip} to {device.ip}"),
                )
            elif not existing["is_online"]:
                conn.execute(
                    """
                    INSERT INTO device_history (mac, ip, event_type, timestamp, details)
                    VALUES (?, ?, 'RECONNECTED', ?, 'Device came back online')
                    """,
                    (norm_mac, device.ip, now),
                )

            return False, (prev_ip if ip_changed else None)

    def get_device_by_mac(self, mac: str) -> Optional[DeviceRecord]:
        """Fetch a single device record by MAC address."""
        norm_mac = mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (norm_mac,)).fetchone()
            if not row:
                return None
            return self._row_to_device(row)

    def get_all_devices(self, online_only: bool = False) -> List[DeviceRecord]:
        """Fetch all known devices ordered by online status and IP."""
        query = "SELECT * FROM devices"
        if online_only:
            query += " WHERE is_online = 1"
        query += " ORDER BY is_online DESC, last_seen DESC"
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(query).fetchall()
            return [self._row_to_device(r) for r in rows]

    def mark_offline_devices(self, active_macs: List[str]) -> int:
        """Mark devices not in `active_macs` as offline. Returns number of devices marked offline."""
        norm_macs = [m.upper().strip() for m in active_macs]
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._get_connection() as conn:
            if not norm_macs:
                going_offline = conn.execute(
                    "SELECT mac, ip FROM devices WHERE is_online = 1"
                ).fetchall()
                cursor = conn.execute("UPDATE devices SET is_online = 0 WHERE is_online = 1")
            else:
                placeholders = ",".join("?" for _ in norm_macs)
                going_offline = conn.execute(
                    f"SELECT mac, ip FROM devices WHERE is_online = 1 AND mac NOT IN ({placeholders})",
                    norm_macs,
                ).fetchall()
                cursor = conn.execute(
                    f"UPDATE devices SET is_online = 0 WHERE is_online = 1 AND mac NOT IN ({placeholders})",
                    norm_macs,
                )
            for row in going_offline:
                conn.execute(
                    """
                    INSERT INTO device_history (mac, ip, event_type, timestamp, details)
                    VALUES (?, ?, 'OFFLINE', ?, 'Device went offline')
                    """,
                    (row["mac"], row["ip"], now),
                )
            return cursor.rowcount

    def get_device_history(self, mac: Optional[str] = None, limit: int = 100) -> List[DeviceHistoryRecord]:
        """Retrieve historical events for a specific device or across all devices."""
        with self._lock, self._get_connection() as conn:
            if mac:
                norm_mac = mac.upper().strip()
                rows = conn.execute(
                    "SELECT * FROM device_history WHERE mac = ? ORDER BY id DESC LIMIT ?",
                    (norm_mac, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM device_history ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [
                DeviceHistoryRecord(
                    id=r["id"],
                    mac=r["mac"],
                    ip=r["ip"],
                    event_type=r["event_type"],
                    timestamp=r["timestamp"],
                    details=r["details"] or "",
                )
                for r in rows
            ]

    def set_device_trusted(self, mac: str, trusted: bool) -> None:
        """Mark or unmark a device as trusted."""
        norm_mac = mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            conn.execute(
                "UPDATE devices SET is_trusted = ? WHERE mac = ?",
                (1 if trusted else 0, norm_mac),
            )

    def update_device_notes(self, mac: str, notes: str, hostname: Optional[str] = None) -> None:
        """Update custom notes and optionally hostname for a device."""
        norm_mac = mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            if hostname is not None:
                conn.execute(
                    "UPDATE devices SET notes = ?, hostname = ? WHERE mac = ?",
                    (notes, hostname, norm_mac),
                )
            else:
                conn.execute(
                    "UPDATE devices SET notes = ? WHERE mac = ?",
                    (notes, norm_mac),
                )

    def update_device_risk(self, mac: str, risk_level: str, risk_score: int) -> None:
        """Update the risk level and score of a device."""
        norm_mac = mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            conn.execute(
                "UPDATE devices SET risk_level = ?, risk_score = ? WHERE mac = ?",
                (risk_level, risk_score, norm_mac),
            )

    def record_alert(self, alert: SecurityAlertRecord) -> int:
        """Insert a security alert and return its ID."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO security_alerts (
                    alert_type, severity, mac, ip, description, is_resolved, timestamp,
                    confidence, first_seen, last_changed, is_acknowledged, acknowledgement_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_type,
                    alert.severity,
                    alert.mac.upper().strip(),
                    alert.ip,
                    alert.description,
                    1 if alert.is_resolved else 0,
                    alert.timestamp,
                    alert.confidence or "HIGH_CONFIDENCE",
                    alert.first_seen,
                    alert.last_changed,
                    1 if alert.is_acknowledged else 0,
                    alert.acknowledgement_notes or "",
                ),
            )
            return int(cursor.lastrowid or 0)

    def resolve_alert(self, alert_id: int) -> None:
        """Mark a specific security alert as resolved."""
        with self._lock, self._get_connection() as conn:
            conn.execute("UPDATE security_alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))

    def acknowledge_alert(
        self,
        alert_id: int,
        notes: str = "",
        mark_resolved: bool = True,
    ) -> bool:
        """Mark an alert as acknowledged by the user as an expected change and optionally resolve it."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE security_alerts
                SET is_acknowledged = 1,
                    acknowledgement_notes = ?,
                    is_resolved = ?
                WHERE id = ?
                """,
                (notes, 1 if mark_resolved else 0, alert_id),
            )
            return cursor.rowcount > 0

    def resolve_all_alerts(self) -> int:
        """Mark all unresolved security alerts as resolved."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute("UPDATE security_alerts SET is_resolved = 1 WHERE is_resolved = 0")
            return cursor.rowcount

    def get_alerts(self, limit: int = 100, unresolved_only: bool = False) -> List[SecurityAlertRecord]:
        """Retrieve recent security alerts."""
        query = "SELECT * FROM security_alerts"
        if unresolved_only:
            query += " WHERE is_resolved = 0"
        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(query, (limit,)).fetchall()
            return [
                SecurityAlertRecord(
                    id=r["id"],
                    alert_type=r["alert_type"],
                    severity=r["severity"],
                    mac=r["mac"],
                    ip=r["ip"],
                    description=r["description"],
                    is_resolved=bool(r["is_resolved"]),
                    timestamp=r["timestamp"],
                    confidence=r["confidence"] if "confidence" in r.keys() and r["confidence"] else "HIGH_CONFIDENCE",
                    first_seen=r["first_seen"] if "first_seen" in r.keys() else None,
                    last_changed=r["last_changed"] if "last_changed" in r.keys() else None,
                    is_acknowledged=bool(r["is_acknowledged"]) if "is_acknowledged" in r.keys() else False,
                    acknowledgement_notes=r["acknowledgement_notes"] if "acknowledgement_notes" in r.keys() and r["acknowledgement_notes"] else "",
                )
                for r in rows
            ]


    def save_port_scan(self, record: PortScanRecord) -> None:
        """Insert or update an open port entry for a device."""
        norm_mac = record.mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO port_scans (mac, ip, port, protocol, service, banner, state, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac, port, protocol) DO UPDATE SET
                    ip = excluded.ip,
                    service = excluded.service,
                    banner = excluded.banner,
                    state = excluded.state,
                    scanned_at = excluded.scanned_at
                """,
                (
                    norm_mac,
                    record.ip,
                    record.port,
                    record.protocol,
                    record.service,
                    record.banner,
                    record.state,
                    record.scanned_at,
                ),
            )

    def sync_host_port_scans(
        self,
        mac: str,
        scanned_ports: List[int],
        open_records: List[PortScanRecord],
        protocol: str = "TCP",
    ) -> None:
        """
        Synchronize port scan results for a host by removing any previously open ports
        within `scanned_ports` that are now closed, and upserting `open_records`.
        """
        norm_mac = mac.upper().strip()
        open_port_set = {rec.port for rec in open_records}
        closed_ports = [int(p) for p in scanned_ports if int(p) not in open_port_set]

        with self._lock, self._get_connection() as conn:
            if closed_ports:
                placeholders = ",".join("?" for _ in closed_ports)
                conn.execute(
                    f"DELETE FROM port_scans WHERE mac = ? AND protocol = ? AND port IN ({placeholders})",
                    [norm_mac, protocol, *closed_ports],
                )
            for record in open_records:
                conn.execute(
                    """
                    INSERT INTO port_scans (mac, ip, port, protocol, service, banner, state, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac, port, protocol) DO UPDATE SET
                        ip = excluded.ip,
                        service = excluded.service,
                        banner = excluded.banner,
                        state = excluded.state,
                        scanned_at = excluded.scanned_at
                    """,
                    (
                        norm_mac,
                        record.ip,
                        record.port,
                        record.protocol,
                        record.service,
                        record.banner,
                        record.state,
                        record.scanned_at,
                    ),
                )

    def get_device_ports(self, mac: str) -> List[PortScanRecord]:
        """Get all discovered open ports for a device."""
        norm_mac = mac.upper().strip()
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM port_scans WHERE mac = ? ORDER BY port ASC",
                (norm_mac,),
            ).fetchall()
            return [
                PortScanRecord(
                    id=r["id"],
                    mac=r["mac"],
                    ip=r["ip"],
                    port=r["port"],
                    protocol=r["protocol"],
                    service=r["service"],
                    banner=r["banner"],
                    state=r["state"],
                    scanned_at=r["scanned_at"],
                )
                for r in rows
            ]

    def get_all_port_scans(self) -> List[PortScanRecord]:
        """Get all discovered open ports across all devices."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM port_scans ORDER BY port ASC").fetchall()
            return [
                PortScanRecord(
                    id=r["id"],
                    mac=r["mac"],
                    ip=r["ip"],
                    port=r["port"],
                    protocol=r["protocol"],
                    service=r["service"],
                    banner=r["banner"],
                    state=r["state"],
                    scanned_at=r["scanned_at"],
                )
                for r in rows
            ]

    def create_scan_session(self, session: ScanSessionRecord) -> int:
        """Start a new scan session record and return its ID."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_sessions (
                    interface_name, subnet_cidr, gateway_ip,
                    devices_found, new_devices, alerts_triggered, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.interface_name,
                    session.subnet_cidr,
                    session.gateway_ip,
                    session.devices_found,
                    session.new_devices,
                    session.alerts_triggered,
                    session.started_at,
                    session.finished_at,
                ),
            )
            return int(cursor.lastrowid or 0)

    def finish_scan_session(
        self, session_id: int, devices_found: int, new_devices: int, alerts_triggered: int
    ) -> None:
        """Update scan session statistics upon completion."""
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                UPDATE scan_sessions
                SET devices_found = ?, new_devices = ?, alerts_triggered = ?, finished_at = ?
                WHERE id = ?
                """,
                (devices_found, new_devices, alerts_triggered, now, session_id),
            )

    def get_recent_sessions(self, limit: int = 50) -> List[ScanSessionRecord]:
        """Retrieve recent scan sessions ordered by started_at DESC."""
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY started_at DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                ScanSessionRecord(
                    id=r["id"],
                    interface_name=r["interface_name"],
                    subnet_cidr=r["subnet_cidr"],
                    gateway_ip=r["gateway_ip"],
                    devices_found=r["devices_found"],
                    new_devices=r["new_devices"],
                    alerts_triggered=r["alerts_triggered"],
                    started_at=r["started_at"],
                    finished_at=r["finished_at"],
                )
                for r in rows
            ]

    def get_dashboard_stats(self) -> Dict[str, int]:
        """Compute summary statistics for the UI dashboard."""
        with self._lock, self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM devices WHERE is_online = 1").fetchone()[0]
            trusted = conn.execute("SELECT COUNT(*) FROM devices WHERE is_trusted = 1").fetchone()[0]
            high_risk = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE risk_level IN ('HIGH', 'CRITICAL')"
            ).fetchone()[0]
            unresolved_alerts = conn.execute(
                "SELECT COUNT(*) FROM security_alerts WHERE is_resolved = 0"
            ).fetchone()[0]
            return {
                "total_devices": total,
                "online_devices": online,
                "offline_devices": total - online,
                "trusted_devices": trusted,
                "high_risk_devices": high_risk,
                "unresolved_alerts": unresolved_alerts,
            }

    @staticmethod
    def _row_to_device(row: sqlite3.Row) -> DeviceRecord:
        return DeviceRecord(
            mac=row["mac"],
            ip=row["ip"],
            hostname=row["hostname"],
            vendor=row["vendor"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            is_online=bool(row["is_online"]),
            is_trusted=bool(row["is_trusted"]),
            risk_level=row["risk_level"],
            risk_score=int(row["risk_score"]),
            notes=row["notes"] or "",
        )

    def export_data_backup(self, target_path: str | Path) -> str:
        """
        Export complete database snapshot (all tables) into a structured JSON backup.
        Returns the absolute string path of the generated export.
        """
        import json

        out_path = Path(target_path).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)

        data: Dict[str, Any] = {
            "version": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "devices": [
                {
                    "mac": d.mac,
                    "ip": d.ip,
                    "hostname": d.hostname,
                    "vendor": d.vendor,
                    "first_seen": d.first_seen,
                    "last_seen": d.last_seen,
                    "is_online": d.is_online,
                    "is_trusted": d.is_trusted,
                    "risk_level": d.risk_level,
                    "risk_score": d.risk_score,
                    "notes": d.notes,
                }
                for d in self.get_all_devices(online_only=False)
            ],
            "security_alerts": [
                {
                    "id": a.id,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "mac": a.mac,
                    "ip": a.ip,
                    "description": a.description,
                    "timestamp": a.timestamp,
                    "is_resolved": a.is_resolved,
                    "confidence": a.confidence,
                    "first_seen": a.first_seen,
                    "last_changed": a.last_changed,
                    "is_acknowledged": a.is_acknowledged,
                    "acknowledgement_notes": a.acknowledgement_notes,
                }
                for a in self.get_alerts(limit=10000, unresolved_only=False)
            ],
            "port_scans": [
                {
                    "mac": p.mac,
                    "ip": p.ip,
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "banner": p.banner,
                    "state": p.state,
                    "scanned_at": p.scanned_at,
                }
                for p in self.get_all_port_scans()
            ],
            "device_history": [
                {
                    "mac": h.mac,
                    "ip": h.ip,
                    "event_type": h.event_type,
                    "timestamp": h.timestamp,
                    "details": h.details,
                }
                for h in self.get_device_history(limit=5000)
            ],
            "scan_sessions": [
                {
                    "interface_name": s.interface_name,
                    "subnet_cidr": s.subnet_cidr,
                    "gateway_ip": s.gateway_ip,
                    "devices_found": s.devices_found,
                    "new_devices": s.new_devices,
                    "alerts_triggered": s.alerts_triggered,
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                }
                for s in self.get_recent_sessions(limit=500)
            ],
        }
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(out_path)

    def clear_all_data(self, keep_trusted_devices: bool = False) -> Dict[str, int]:
        """
        Purge stored network telemetry, alerts, and history.
        Optionally retains devices flagged as is_trusted=True.
        Runs VACUUM to reclaim SQLite page space.
        """
        with self._lock:
            with self._get_connection() as conn:
                p_cnt = conn.execute("DELETE FROM port_scans;").rowcount
                a_cnt = conn.execute("DELETE FROM security_alerts;").rowcount
                h_cnt = conn.execute("DELETE FROM device_history;").rowcount
                s_cnt = conn.execute("DELETE FROM scan_sessions;").rowcount

                if keep_trusted_devices:
                    d_cnt = conn.execute("DELETE FROM devices WHERE is_trusted = 0;").rowcount
                else:
                    d_cnt = conn.execute("DELETE FROM devices;").rowcount

            try:
                vac_conn = self._get_connection()
                try:
                    old_iso = vac_conn.isolation_level
                    vac_conn.isolation_level = None
                    vac_conn.execute("VACUUM;")
                    vac_conn.isolation_level = old_iso
                finally:
                    vac_conn.close()
            except Exception as exc:
                logger.debug("VACUUM after purge skipped: %s", exc)

            return {
                "devices": d_cnt,
                "devices_deleted": d_cnt,
                "port_scans": p_cnt,
                "security_alerts": a_cnt,
                "device_history": h_cnt,
                "scan_sessions": s_cnt,
            }

    def prune_old_records(self, retention_days: int = 30) -> Dict[str, int]:
        """
        Prune device history, scan sessions, and resolved security alerts older than `retention_days`.
        """
        from datetime import datetime, timedelta

        cutoff = (datetime.now() - timedelta(days=max(1, retention_days))).isoformat(timespec="seconds")

        with self._lock, self._get_connection() as conn:
            h_cnt = conn.execute("DELETE FROM device_history WHERE timestamp < ?;", (cutoff,)).rowcount
            s_cnt = conn.execute("DELETE FROM scan_sessions WHERE started_at < ?;", (cutoff,)).rowcount
            a_cnt = conn.execute(
                "DELETE FROM security_alerts WHERE is_resolved = 1 AND timestamp < ?;",
                (cutoff,),
            ).rowcount

            return {
                "device_history": h_cnt,
                "scan_sessions": s_cnt,
                "security_alerts": a_cnt,
            }


