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
from src.utils.logger import resolve_data_path


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
        """Create all required tables and indexes if they do not exist."""
        with self._lock, self._get_connection() as conn:
            conn.executescript(
                """
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
                    timestamp TEXT NOT NULL
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
                    alert_type, severity, mac, ip, description, is_resolved, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_type,
                    alert.severity,
                    alert.mac.upper().strip(),
                    alert.ip,
                    alert.description,
                    1 if alert.is_resolved else 0,
                    alert.timestamp,
                ),
            )
            return int(cursor.lastrowid)

    def resolve_alert(self, alert_id: int) -> None:
        """Mark a specific security alert as resolved."""
        with self._lock, self._get_connection() as conn:
            conn.execute("UPDATE security_alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))

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
            return int(cursor.lastrowid)

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

