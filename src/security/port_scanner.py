"""Concurrent TCP port scanner and service banner grabber."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from src.database.db_manager import DatabaseManager
from src.database.models import PortScanRecord
from src.utils.logger import setup_logger

logger = setup_logger("PortScanner")

COMMON_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds (SMB)",
    554: "rtsp",
    1433: "ms-sql-s",
    1883: "mqtt",
    2375: "docker",
    3306: "mysql",
    3389: "ms-wbt-server (RDP)",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9100: "jetdirect",
}

DEFAULT_SCAN_PORTS: List[int] = [
    21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 1883, 3306, 3389, 5900, 8080, 8443
]

HIGH_RISK_PORTS: Dict[int, str] = {
    21: "Unencrypted FTP service exposed",
    23: "Insecure cleartext Telnet service exposed",
    445: "SMB file sharing port exposed (lateral movement / ransomware risk)",
    2375: "Unencrypted Docker daemon API exposed",
    3389: "Remote Desktop Protocol (RDP) exposed",
    5900: "VNC remote desktop service exposed",
    6379: "Redis datastore port exposed",
}


class PortScanner:
    """Multi-threaded TCP port scanner with service identification and banner grabbing."""

    def __init__(
        self,
        timeout: float = 0.45,
        max_workers: int = 32,
        grab_banners: bool = True,
    ) -> None:
        self.timeout = max(0.05, float(timeout))
        self.max_workers = max(2, min(max_workers, 128))
        self.grab_banners = grab_banners

    @staticmethod
    def get_service_name(port: int) -> str:
        """Return known service name for a TCP port."""
        if port in COMMON_SERVICES:
            return COMMON_SERVICES[port]
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    def probe_port(self, ip: str, port: int, mac: str = "00:00:00:00:00:00") -> Optional[PortScanRecord]:
        """
        Attempt a TCP connection to `(ip, port)`.
        Returns a `PortScanRecord` if the port is open, or `None` if closed/filtered.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, int(port)))
                if result != 0:
                    return None

                service = self.get_service_name(port)
                banner = ""
                if self.grab_banners:
                    banner = self._try_grab_banner(sock, ip, port)

                return PortScanRecord(
                    mac=mac.upper().strip(),
                    ip=ip,
                    port=int(port),
                    protocol="TCP",
                    service=service,
                    banner=banner,
                    state="OPEN",
                    scanned_at=datetime.now().isoformat(timespec="seconds"),
                )
        except OSError:
            return None

    def _try_grab_banner(self, sock: socket.socket, ip: str, port: int) -> str:
        """Attempt a quick non-intrusive banner read on an open socket."""
        try:
            sock.settimeout(min(0.25, self.timeout))
            if port in (80, 8000, 8080):
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii", errors="ignore"))
            raw = sock.recv(256)
            if not raw:
                return ""
            text = raw.decode("utf-8", errors="replace").strip()
            first_line = text.splitlines()[0].strip() if text else ""
            # Sanitize printable ASCII
            clean = "".join(ch for ch in first_line if 32 <= ord(ch) <= 126)
            return clean[:120]
        except OSError:
            return ""

    def scan_host(
        self,
        ip: str,
        mac: str = "00:00:00:00:00:00",
        ports: Optional[Sequence[int]] = None,
        db: Optional[DatabaseManager] = None,
    ) -> List[PortScanRecord]:
        """
        Concurrently scan multiple TCP ports on `ip`.
        If `db` is provided, persists discovered open ports to SQLite.
        """
        target_ports = list(dict.fromkeys(ports if ports is not None else DEFAULT_SCAN_PORTS))
        if not target_ports:
            return []

        open_records: List[PortScanRecord] = []
        workers = min(self.max_workers, len(target_ports))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.probe_port, ip, port, mac): port
                for port in target_ports
            }
            for future in as_completed(futures):
                try:
                    record = future.result()
                    if record is not None:
                        open_records.append(record)
                except Exception as exc:
                    logger.debug("Error scanning %s:%s — %s", ip, futures[future], exc)

        open_records.sort(key=lambda r: r.port)

        if db is not None and mac and mac != "00:00:00:00:00:00":
            db.sync_host_port_scans(
                mac=mac,
                scanned_ports=[int(p) for p in target_ports],
                open_records=open_records,
            )

        return open_records
