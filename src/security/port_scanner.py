"""Concurrent TCP port scanner and service banner grabber."""

import errno
import select
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

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
        rate_limit_delay_ms: float = 0.0,
    ) -> None:
        self.timeout = max(0.05, float(timeout))
        self.max_workers = max(2, min(max_workers, 128))
        self.grab_banners = grab_banners
        self.rate_limit_delay_ms = max(0.0, float(rate_limit_delay_ms))

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
        Logs any non-zero errno or OSError code at DEBUG level for diagnostics.
        """
        target_port = int(port)
        if self.rate_limit_delay_ms > 0:
            time.sleep(self.rate_limit_delay_ms / 1000.0)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, target_port))
                if result in (errno.EINPROGRESS, errno.EWOULDBLOCK, 10035, 10036):
                    _, writable, exceptional = select.select([], [sock], [sock], self.timeout)
                    if writable or exceptional:
                        result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if result == 0 and not writable:
                            result = errno.ECONNREFUSED
                    else:
                        result = getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT)

                if result != 0:
                    err_name = errno.errorcode.get(result, "CLOSED_OR_FILTERED")
                    logger.debug(
                        "TCP probe %s:%d closed/filtered (errno=%d, %s)",
                        ip,
                        target_port,
                        result,
                        err_name,
                    )
                    return None

                service = self.get_service_name(target_port)
                banner = ""
                if self.grab_banners:
                    banner = self._try_grab_banner(sock, ip, target_port)

                return PortScanRecord(
                    mac=mac.upper().strip(),
                    ip=ip,
                    port=target_port,
                    protocol="TCP",
                    service=service,
                    banner=banner,
                    state="OPEN",
                    scanned_at=datetime.now().isoformat(timespec="seconds"),
                )
        except OSError as exc:
            err_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None) or -1
            err_name = (
                errno.errorcode.get(int(err_code), type(exc).__name__)
                if isinstance(err_code, int)
                else type(exc).__name__
            )
            logger.debug(
                "TCP probe %s:%d raised OSError (errno=%s, %s): %s",
                ip,
                target_port,
                err_code,
                err_name,
                exc,
            )
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
        except OSError as exc:
            err_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None) or -1
            logger.debug("Banner read on %s:%d ended (errno=%s): %s", ip, port, err_code, exc)
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

    @classmethod
    def run_localhost_verification(
        cls,
        banner_text: str = "SSH-2.0-NetworkSentryTest",
        port: Optional[int] = None,
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Self-contained localhost port verification test mode.
        Spins up a temporary ephemeral local TCP socket, probes it using PortScanner,
        confirms detection, verifies negative check on a closed port, and cleans up.
        Returns a dictionary containing test results and diagnostic details.
        """
        import threading
        import time

        server_sock: Optional[socket.socket] = None
        listener_ready = threading.Event()
        shutdown_event = threading.Event()
        server_error: List[str] = []

        target_port = int(port) if port is not None and port > 0 else 0

        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("127.0.0.1", target_port))
            server_sock.listen(1)
            actual_open_port = server_sock.getsockname()[1]
        except OSError as exc:
            if server_sock:
                server_sock.close()
            return {
                "success": False,
                "open_port": target_port,
                "closed_port": None,
                "detected": False,
                "banner_matched": False,
                "negative_check_passed": False,
                "message": f"Failed to bind ephemeral server socket on 127.0.0.1:{target_port}: {exc}",
            }

        def _serve() -> None:
            listener_ready.set()
            try:
                server_sock.settimeout(2.5)
                conn, _ = server_sock.accept()
                with conn:
                    if banner_text:
                        conn.sendall(f"{banner_text}\r\n".encode("utf-8"))
                    time.sleep(0.05)
            except OSError as e:
                if not shutdown_event.is_set():
                    server_error.append(str(e))

        th = threading.Thread(target=_serve, daemon=True)
        th.start()
        listener_ready.wait(timeout=1.5)

        # Find a port that is definitely closed
        closed_port = None
        for cand in [actual_open_port + 1, actual_open_port + 3, actual_open_port + 7, (actual_open_port + 100) % 60000 + 1024]:
            if cand > 65535 or cand == actual_open_port:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(0.08)
                    if probe.connect_ex(("127.0.0.1", cand)) != 0:
                        closed_port = cand
                        break
            except OSError:
                closed_port = cand
                break
        if closed_port is None:
            closed_port = 65432

        scanner = cls(timeout=timeout, grab_banners=bool(banner_text))
        t0 = time.monotonic()
        open_record = scanner.probe_port("127.0.0.1", actual_open_port)
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        closed_record = scanner.probe_port("127.0.0.1", closed_port)

        shutdown_event.set()
        try:
            server_sock.close()
        except OSError:
            pass
        th.join(timeout=1.0)

        detected = open_record is not None and open_record.state == "OPEN"
        banner_matched = bool(open_record and banner_text and banner_text in open_record.banner) if banner_text else True
        negative_passed = closed_record is None

        success = detected and negative_passed and banner_matched

        msg = (
            f"Localhost Port Verification PASSED: Open port {actual_open_port} detected in {elapsed_ms:.1f}ms "
            f"(Banner: '{open_record.banner if open_record else ''}'), closed port {closed_port} correctly rejected."
            if success
            else f"Localhost Port Verification FAILED: detected={detected}, negative_check={negative_passed}, errors={server_error}"
        )

        return {
            "success": success,
            "host": "127.0.0.1",
            "port": actual_open_port,
            "open_port": actual_open_port,
            "closed_port": closed_port,
            "detected": detected,
            "state": "OPEN" if detected else "CLOSED",
            "service": open_record.service if open_record else "unknown",
            "banner": open_record.banner if open_record else "",
            "banner_matched": banner_matched,
            "negative_check_passed": negative_passed,
            "elapsed_ms": round(elapsed_ms, 2),
            "record": open_record,
            "message": msg,
            "error": None if success else msg,
        }

