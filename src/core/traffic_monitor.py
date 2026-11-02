"""Real-time network telemetry, packet rate, flow statistics, and NQL filtering engine."""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Optional, Tuple

import psutil

from src.database.db_manager import DatabaseManager
from src.native.c_bridge import NativePacketEngine
from src.security.port_scanner import DEFAULT_SCAN_PORTS

TCP_FLAG_SERIES: List[Tuple[str, str, str]] = [
    ("ACK SYN FIN", "#F59E0B", "square"),
    ("SYN", "#EF4444", "diamond"),
    ("No flags set", "#10B981", "square"),
    ("ACK SYN", "#F43F5E", "triangle"),
    ("URG PSH SYN FIN", "#A855F7", "inv_triangle"),
    ("ACK PSH", "#22C55E", "circle"),
    ("SYN FIN", "#EAB308", "diamond"),
    ("ACK PSH SYN", "#8B5CF6", "square"),
    ("ACK FIN", "#38BDF8", "triangle"),
    ("ACK PSH FIN", "#6366F1", "inv_triangle"),
]


@dataclass
class TrafficSample:
    """Single time-series telemetry datapoint."""

    timestamp: str
    full_timestamp: str
    bitrate_mbps: float
    tcp_mbps: float
    udp_mbps: float
    packets_per_sec: float
    flow_rate_fps: float
    unique_ips: int
    site_mbps: float
    gateway_mbps: float
    vendor_breakdown: Dict[str, float] = field(default_factory=dict)
    tcp_flags: Dict[str, float] = field(default_factory=dict)
    is_estimated: bool = True


@dataclass
class TelemetrySnapshot:
    """Aggregated telemetry state for the Cyber Guardian Dashboard & Traffic Overview."""

    total_packets: int
    total_packets_formatted: str
    bits_per_sec_mbps: float
    bits_per_sec_formatted: str
    open_ports: int
    closed_ports: int
    filtered_ports: int
    top_protocols: List[Tuple[str, int]]
    protocol_breakdown: List[Tuple[str, float, str]]
    port_breakdown: List[Tuple[str, float, str]]
    samples: List[TrafficSample]
    spiral_intensities: List[float]
    active_nql: str = ""
    is_estimated: bool = True
    telemetry_mode: str = "ESTIMATED_NIC"
    telemetry_label: str = "OS NIC Counters + Estimated Telemetry (Demo/Estimated without Live Pcap)"


class TrafficMonitor:
    """Collects live NIC packet/byte counters, active OS socket flows, C-engine packet captures, and DB port metrics."""

    def __init__(
        self,
        max_samples: int = 60,
        demo_mode: bool = False,
        c_engine: Optional[NativePacketEngine] = None,
    ) -> None:
        self.max_samples = max(20, max_samples)
        self.demo_mode = bool(demo_mode)
        self.c_engine = c_engine
        self._samples: Deque[TrafficSample] = deque(maxlen=self.max_samples)
        self._last_io_time: float = time.monotonic()
        self._last_bytes: int = 0
        self._last_packets: int = 0
        self._base_packets: int = 0
        self._tick: int = 0

        # Accumulators for real raw packets ingested via NativePacketEngine
        self._ingested_packets_total: int = 0
        self._ingested_tcp_packets: int = 0
        self._ingested_udp_packets: int = 0
        self._ingested_icmp_packets: int = 0
        self._ingested_arp_packets: int = 0
        self._ingested_port_counts: Dict[int, int] = {}
        self._last_os_tcp_flows: int = 0
        self._last_os_udp_flows: int = 0
        self._window_bytes: int = 0
        self._window_tcp_bytes: int = 0
        self._window_udp_bytes: int = 0
        self._window_icmp_bytes: int = 0
        self._window_packets: int = 0
        self._window_ips: set[str] = set()
        self._window_tcp_flags: Dict[str, float] = {}

        self._init_counters()
        self._seed_initial_history()

    def set_demo_mode(self, enabled: bool) -> None:
        """Enable or disable synthetic demo waveform mode and reset baseline samples."""
        self.demo_mode = bool(enabled)
        self._samples.clear()
        self._seed_initial_history()

    def _init_counters(self) -> None:
        try:
            io = psutil.net_io_counters(pernic=False)
            if io:
                self._last_bytes = int(io.bytes_sent + io.bytes_recv)
                self._last_packets = int(io.packets_sent + io.packets_recv)
                self._base_packets = self._last_packets
        except Exception:
            self._last_bytes = 0
            self._last_packets = 0
            self._base_packets = 0
        self._last_io_time = time.monotonic()

    @staticmethod
    def decode_tcp_flags_label(flags_mask: int) -> str:
        """Map a 6-bit TCP header flags bitmask to its display series name."""
        mask = int(flags_mask) & 0x3F
        if mask == 0:
            return "No flags set"
        fin = bool(mask & 0x01)
        syn = bool(mask & 0x02)
        psh = bool(mask & 0x08)
        ack = bool(mask & 0x10)
        urg = bool(mask & 0x20)

        if urg and psh and syn and fin:
            return "URG PSH SYN FIN"
        if ack and syn and fin:
            return "ACK SYN FIN"
        if ack and psh and syn:
            return "ACK PSH SYN"
        if ack and psh and fin:
            return "ACK PSH FIN"
        if syn and fin:
            return "SYN FIN"
        if ack and syn:
            return "ACK SYN"
        if ack and psh:
            return "ACK PSH"
        if ack and fin:
            return "ACK FIN"
        if syn:
            return "SYN"
        if ack:
            return "ACK PSH"
        if fin:
            return "ACK FIN"
        return "No flags set"

    def ingest_raw_packet(self, raw_bytes: bytes) -> bool:
        """
        Parse and ingest a live raw Ethernet frame using the Native C Packet Engine.
        Returns True if the frame was valid IPv4 or ARP and recorded in live capture counters.
        """
        if not raw_bytes:
            return False
        engine = self.c_engine or NativePacketEngine(auto_compile=False)
        self.c_engine = engine

        ip_pkt = engine.parse_ipv4_packet(raw_bytes)
        if ip_pkt is not None and ip_pkt.is_valid:
            pkt_len = max(len(raw_bytes), ip_pkt.total_length)
            self._ingested_packets_total += 1
            self._window_packets += 1
            self._window_bytes += pkt_len
            if ip_pkt.src_ip:
                self._window_ips.add(ip_pkt.src_ip)
            if ip_pkt.dst_ip:
                self._window_ips.add(ip_pkt.dst_ip)
            if ip_pkt.dst_port > 0:
                self._ingested_port_counts[ip_pkt.dst_port] = (
                    self._ingested_port_counts.get(ip_pkt.dst_port, 0) + 1
                )
            if ip_pkt.protocol == 6:
                self._ingested_tcp_packets += 1
                self._window_tcp_bytes += pkt_len
                lbl = self.decode_tcp_flags_label(ip_pkt.tcp_flags)
                self._window_tcp_flags[lbl] = self._window_tcp_flags.get(lbl, 0.0) + 1.0
            elif ip_pkt.protocol == 17:
                self._ingested_udp_packets += 1
                self._window_udp_bytes += pkt_len
            elif ip_pkt.protocol == 1:
                self._ingested_icmp_packets += 1
                self._window_icmp_bytes += pkt_len
            return True

        arp_pkt = engine.parse_arp_packet(raw_bytes)
        if arp_pkt is not None and arp_pkt.is_valid:
            self._ingested_packets_total += 1
            self._ingested_arp_packets += 1
            self._window_packets += 1
            self._window_bytes += len(raw_bytes)
            if arp_pkt.src_ip:
                self._window_ips.add(arp_pkt.src_ip)
            return True

        return False

    def _seed_initial_history(self) -> None:
        """
        Initialize the rolling time-series window.
        When `demo_mode` is False (default), seeds zero-valued baseline slots rather than
        fabricating synthetic traffic history. When `demo_mode` is True, populates synthetic demo waves.
        """
        now = datetime.now()
        for i in range(36, 0, -1):
            ts = now - timedelta(minutes=i * 2)
            if not self.demo_mode:
                self._samples.append(
                    TrafficSample(
                        timestamp=ts.strftime("%H:%M"),
                        full_timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                        bitrate_mbps=0.0,
                        tcp_mbps=0.0,
                        udp_mbps=0.0,
                        packets_per_sec=0.0,
                        flow_rate_fps=0.0,
                        unique_ips=0,
                        site_mbps=0.0,
                        gateway_mbps=0.0,
                        vendor_breakdown={
                            "LAN-Core": 0.0,
                            "Gateway": 0.0,
                            "Workstations": 0.0,
                            "IoT-Nodes": 0.0,
                            "External": 0.0,
                        },
                        tcp_flags={name: 0.0 for name, _, _ in TCP_FLAG_SERIES},
                        is_estimated=True,
                    )
                )
                continue

            phase = (36 - i) * 0.28
            wave1 = math.sin(phase) * 0.5 + 0.5
            wave2 = math.cos(phase * 0.7) * 0.5 + 0.5
            spike = 1.85 if i in (14, 10, 6) else 1.0

            tcp_val = round((48.0 + 145.0 * wave1) * spike, 2)
            udp_val = round((28.0 + 95.0 * wave2) * (1.35 if i in (11, 6) else 1.0), 2)
            total_mbps = round(tcp_val + udp_val, 2)
            pps = round((total_mbps * 52.0) + 1200.0 * wave1, 1)
            fps = round(65.0 + 180.0 * wave1 * spike, 1)
            uniq_ips = int(12 + 24 * wave2 + (15 if spike > 1.0 else 0))

            flags: Dict[str, float] = {
                "ACK SYN FIN": round(3200.0 + 4800.0 * wave1, 1),
                "SYN": round(450.0 + (12500.0 if spike > 1.0 else 650.0 * wave2), 1),
                "No flags set": round(55.0 + 35.0 * wave1, 2),
                "ACK SYN": round(28.0 + 45.0 * wave2, 2),
                "URG PSH SYN FIN": round(1.5 + 6.0 * wave1, 2),
                "ACK PSH": round(62.0 + 25.0 * wave2, 2),
                "SYN FIN": round(180.0 + 220.0 * wave1, 1),
                "ACK PSH SYN": round(8.0 + 14.0 * wave2, 2),
                "ACK FIN": round(14.0 + 19.0 * wave1, 2),
                "ACK PSH FIN": round(4.0 + 7.0 * wave2, 2),
            }

            self._samples.append(
                TrafficSample(
                    timestamp=ts.strftime("%H:%M"),
                    full_timestamp=ts.strftime("%Y-%m-%d %H:%M:%S"),
                    bitrate_mbps=total_mbps,
                    tcp_mbps=tcp_val,
                    udp_mbps=udp_val,
                    packets_per_sec=pps,
                    flow_rate_fps=fps,
                    unique_ips=uniq_ips,
                    site_mbps=round(total_mbps * 0.62, 2),
                    gateway_mbps=round(total_mbps * 0.38, 2),
                    vendor_breakdown={
                        "LAN-Core": round(total_mbps * 0.34, 1),
                        "Gateway": round(total_mbps * 0.26, 1),
                        "Workstations": round(total_mbps * 0.18, 1),
                        "IoT-Nodes": round(total_mbps * 0.13, 1),
                        "External": round(total_mbps * 0.09, 1),
                    },
                    tcp_flags=flags,
                    is_estimated=True,
                )
            )

    @staticmethod
    def format_packet_count(count: int) -> str:
        """Format packet count cleanly like '1.2M' or '482.4K'."""
        if count >= 1_000_000:
            return f"{count / 1_000_000:.1f}M"
        if count >= 1_000:
            return f"{count / 1_000:.1f}K"
        return str(max(0, count))

    @staticmethod
    def format_Mbps(mbps: float) -> str:
        """Format throughput cleanly like '154Mbps', '24.8Mbps', or '0.00Mbps'."""
        if mbps >= 100.0:
            return f"{int(round(mbps))}Mbps"
        if mbps >= 1.0:
            return f"{mbps:.1f}Mbps"
        return f"{max(0.0, mbps):.2f}Mbps"

    @staticmethod
    def evaluate_nql_clause(clause: str, rec) -> Optional[bool]:
        """
        Evaluate a single atomic NQL predicate against a PortScanRecord.
        Returns True/False if the predicate applies to port/host records, or None if it is
        purely a protocol-level traffic filter (e.g. `proto == udp` when port records are TCP).
        """
        import ipaddress
        import re

        c = clause.strip()
        while c.startswith("(") and c.endswith(")"):
            c = c[1:-1].strip()
        if not c:
            return True

        m = re.match(r"^([a-zA-Z0-9_.\-]+)\s*(==|!=|>=|<=|>|<|=)\s*(.+)$", c)
        if not m:
            hay = f"{rec.ip} {rec.mac} {rec.port} {rec.protocol} {rec.service}".lower()
            return c.lower() in hay

        field_name = m.group(1).strip().lower()
        op = m.group(2).strip()
        if op == "=":
            op = "=="
        raw_val = m.group(3).strip().strip("\"'").lower()

        if field_name in ("port", "srcport", "dstport"):
            try:
                target_port = int(raw_val)
            except ValueError:
                return False
            actual_port = int(rec.port)
            if op == "==":
                return actual_port == target_port
            if op == "!=":
                return actual_port != target_port
            if op == ">=":
                return actual_port >= target_port
            if op == "<=":
                return actual_port <= target_port
            if op == ">":
                return actual_port > target_port
            if op == "<":
                return actual_port < target_port

        if field_name in ("proto", "protocol"):
            actual_proto = str(rec.protocol).lower()
            if op == "==":
                return actual_proto == raw_val
            if op == "!=":
                return actual_proto != raw_val
            return False

        if field_name in ("ip", "srcip", "dstip", "host"):
            actual_ip = str(rec.ip).strip()
            if "/" in raw_val:
                try:
                    net = ipaddress.ip_network(raw_val, strict=False)
                    in_net = ipaddress.ip_address(actual_ip) in net
                    return in_net if op == "==" else (not in_net if op == "!=" else False)
                except ValueError:
                    pass
            if op == "==":
                return actual_ip.lower() == raw_val
            if op == "!=":
                return actual_ip.lower() != raw_val
            return actual_ip.lower().startswith(raw_val)

        if field_name == "mac":
            actual_mac = str(rec.mac).lower()
            return (actual_mac == raw_val) if op == "==" else (actual_mac != raw_val)

        if field_name in ("service", "svc", "app"):
            actual_svc = str(rec.service).lower()
            if op == "==":
                return actual_svc == raw_val or raw_val in actual_svc
            if op == "!=":
                return actual_svc != raw_val and raw_val not in actual_svc
            return False

        return True

    @classmethod
    def matches_nql(cls, query: str, rec) -> bool:
        """Evaluate compound NQL query (`AND`/`&&`, `OR`/`||`) against a PortScanRecord."""
        import re

        q = query.strip()
        if not q:
            return True

        or_groups = re.split(r"\s+(?:OR|\|\|)\s+", q, flags=re.IGNORECASE)
        for grp in or_groups:
            and_clauses = re.split(r"\s+(?:AND|&&)\s+", grp, flags=re.IGNORECASE)
            group_ok = True
            for clause in and_clauses:
                res = cls.evaluate_nql_clause(clause, rec)
                if res is False:
                    group_ok = False
                    break
            if group_ok:
                return True
        return False

    @staticmethod
    def extract_nql_proto_focus(query: str) -> Optional[str]:
        """Return 'tcp', 'udp', or 'icmp' if NQL query explicitly focuses on a protocol."""
        import re

        q = query.strip().lower()
        if not q:
            return None
        for m in re.finditer(r"(?:proto|protocol)\s*(==|!=|=)\s*([a-z0-9]+)", q):
            op, val = m.group(1), m.group(2)
            if op in ("==", "=") and val in ("tcp", "udp", "icmp"):
                return val
            if op == "!=" and val == "tcp":
                return "udp"
            if op == "!=" and val == "udp":
                return "tcp"
        if q in ("tcp", "udp", "icmp"):
            return q
        return None

    @staticmethod
    def _sample_os_socket_telemetry(online_ips: Optional[List[str]] = None) -> Tuple[int, int, int, Dict[str, float]]:
        """
        Inspect active OS inet socket connections via `psutil.net_connections` to obtain
        real TCP/UDP flow counts, unique peer IP cardinality, and socket-state flag estimates.
        """
        import socket as _sock

        tcp_flows = 0
        udp_flows = 0
        peer_ips: set[str] = set(online_ips or [])
        flags: Dict[str, float] = {name: 0.0 for name, _, _ in TCP_FLAG_SERIES}

        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.raddr and getattr(c.raddr, "ip", None):
                    rip = str(c.raddr.ip)
                    if not rip.startswith("127.") and rip not in ("0.0.0.0", "::", "::1"):
                        peer_ips.add(rip)
                if c.type == _sock.SOCK_STREAM:
                    tcp_flows += 1
                    st = str(getattr(c, "status", "")).upper()
                    if st == "ESTABLISHED":
                        flags["ACK PSH"] = flags.get("ACK PSH", 0.0) + 1.0
                    elif st == "SYN_SENT":
                        flags["SYN"] = flags.get("SYN", 0.0) + 1.0
                    elif st in ("SYN_RECV", "SYN_RCVD"):
                        flags["ACK SYN"] = flags.get("ACK SYN", 0.0) + 1.0
                    elif st in ("FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "TIME_WAIT", "LAST_ACK"):
                        flags["ACK FIN"] = flags.get("ACK FIN", 0.0) + 1.0
                    elif st == "LISTEN":
                        flags["No flags set"] = flags.get("No flags set", 0.0) + 1.0
                elif c.type == _sock.SOCK_DGRAM:
                    udp_flows += 1
        except Exception:
            pass

        return tcp_flows, udp_flows, len(peer_ips), flags

    def record_tick(
        self,
        db: Optional[DatabaseManager] = None,
        interface_name: Optional[str] = None,
        timeline_position: float = 1.0,
        nql_query: str = "",
        window_mode: str = "Live Timeline",
        metric_mode: str = "bitrate",
    ) -> TelemetrySnapshot:
        """Sample live OS network counters, merge with DB state, and return a TelemetrySnapshot."""
        self._tick += 1
        now = time.monotonic()
        dt = max(0.2, now - self._last_io_time)
        self._last_io_time = now

        cur_bytes = self._last_bytes
        cur_packets = self._last_packets
        try:
            if interface_name:
                pernic = psutil.net_io_counters(pernic=True)
                nic_io = pernic.get(interface_name)
                if nic_io is None:
                    nic_io = psutil.net_io_counters(pernic=False)
            else:
                nic_io = psutil.net_io_counters(pernic=False)
            if nic_io:
                cur_bytes = int(nic_io.bytes_sent + nic_io.bytes_recv)
                cur_packets = int(nic_io.packets_sent + nic_io.packets_recv)
        except Exception:
            pass

        delta_bytes = max(0, cur_bytes - self._last_bytes)
        delta_packets = max(0, cur_packets - self._last_packets)
        self._last_bytes = cur_bytes
        self._last_packets = cur_packets

        measured_mbps = (delta_bytes * 8.0) / (dt * 1_000_000.0)
        measured_pps = delta_packets / dt

        # Query DB devices, open ports, and alerts for live network context
        online_devices = db.get_all_devices(online_only=True) if db else []
        all_devices = db.get_all_devices(online_only=False) if db else []
        unresolved_alerts = db.get_alerts(unresolved_only=True) if db else []
        dt_now = datetime.now()

        if self._window_packets > 0 and not self.demo_mode:
            # 1. Live Raw Packet Capture path (ingested via NativePacketEngine)
            cap_mbps = (self._window_bytes * 8.0) / (dt * 1_000_000.0)
            total_mbps = round(max(measured_mbps, cap_mbps), 2)
            tcp_ratio = self._window_tcp_bytes / max(1, self._window_bytes)
            udp_ratio = self._window_udp_bytes / max(1, self._window_bytes)
            tcp_mbps = round(total_mbps * tcp_ratio, 2)
            udp_mbps = round(total_mbps * udp_ratio, 2)
            pps = round(max(measured_pps, self._window_packets / dt), 1)
            fps = round(float(len(self._window_ips)), 1)
            uniq_ips = max(len(online_devices), len(self._window_ips))
            flags = {name: round(self._window_tcp_flags.get(name, 0.0), 2) for name, _, _ in TCP_FLAG_SERIES}
            is_estimated = False

            self._window_bytes = 0
            self._window_tcp_bytes = 0
            self._window_udp_bytes = 0
            self._window_icmp_bytes = 0
            self._window_packets = 0
            self._window_ips.clear()
            self._window_tcp_flags.clear()
        elif not self.demo_mode:
            # 2. Honest OS NIC Counters + Active Socket Telemetry (No synthetic sine waves!)
            online_ips = [d.ip for d in online_devices if d.ip]
            tcp_flows, udp_flows, uniq_ips_count, sock_flags = self._sample_os_socket_telemetry(online_ips)
            self._last_os_tcp_flows = tcp_flows
            self._last_os_udp_flows = udp_flows
            total_flows = max(1, tcp_flows + udp_flows)
            tcp_share = (tcp_flows / total_flows) if (tcp_flows + udp_flows) > 0 else 0.75

            total_mbps = round(measured_mbps, 2)
            tcp_mbps = round(total_mbps * tcp_share, 2)
            udp_mbps = round(max(0.0, total_mbps - tcp_mbps), 2)
            pps = round(measured_pps, 1)
            fps = round(float(tcp_flows + udp_flows), 1)
            uniq_ips = max(len(online_devices), uniq_ips_count)
            flags = sock_flags
            is_estimated = True
        else:
            # 3. Explicit Demo / Synthetic Telemetry Mode (only when demo_mode=True)
            phase = self._tick * 0.35
            wave_tcp = math.sin(phase) * 0.5 + 0.5
            wave_udp = math.cos(phase * 0.8 + 1.1) * 0.5 + 0.5
            alert_boost = 1.0 + min(1.2, len(unresolved_alerts) * 0.22)

            tcp_mbps = round(max(measured_mbps * 0.72, (62.0 + 135.0 * wave_tcp) * alert_boost), 2)
            udp_mbps = round(max(measured_mbps * 0.28, (32.0 + 88.0 * wave_udp) * alert_boost), 2)
            total_mbps = round(tcp_mbps + udp_mbps, 2)
            pps = round(max(measured_pps, total_mbps * 58.0 + 950.0 * wave_tcp), 1)
            fps = round(70.0 + len(online_devices) * 14.0 + 120.0 * wave_tcp * alert_boost, 1)
            uniq_ips = max(len(online_devices), int(14 + 18 * wave_udp + len(all_devices) * 2))
            flags = {
                "ACK SYN FIN": round(3400.0 + 4600.0 * wave_tcp, 1),
                "SYN": round(520.0 + (9800.0 if unresolved_alerts else 700.0 * wave_udp), 1),
                "No flags set": round(58.0 + 30.0 * wave_tcp, 2),
                "ACK SYN": round(32.0 + 40.0 * wave_udp, 2),
                "URG PSH SYN FIN": round(2.0 + (18.0 if unresolved_alerts else 4.0 * wave_tcp), 2),
                "ACK PSH": round(64.0 + 22.0 * wave_udp, 2),
                "SYN FIN": round(190.0 + 210.0 * wave_tcp, 1),
                "ACK PSH SYN": round(9.0 + 12.0 * wave_udp, 2),
                "ACK FIN": round(15.0 + 18.0 * wave_tcp, 2),
                "ACK PSH FIN": round(4.5 + 6.5 * wave_udp, 2),
            }
            is_estimated = True

        sample = TrafficSample(
            timestamp=dt_now.strftime("%H:%M:%S"),
            full_timestamp=dt_now.strftime("%Y-%m-%d %H:%M:%S"),
            bitrate_mbps=total_mbps,
            tcp_mbps=tcp_mbps,
            udp_mbps=udp_mbps,
            packets_per_sec=pps,
            flow_rate_fps=fps,
            unique_ips=uniq_ips,
            site_mbps=round(total_mbps * 0.64, 2),
            gateway_mbps=round(total_mbps * 0.36, 2),
            vendor_breakdown={
                "LAN-Core": round(total_mbps * 0.35, 1),
                "Gateway": round(total_mbps * 0.25, 1),
                "Workstations": round(total_mbps * 0.18, 1),
                "IoT-Nodes": round(total_mbps * 0.13, 1),
                "External": round(total_mbps * 0.09, 1),
            },
            tcp_flags=flags,
            is_estimated=is_estimated,
        )
        self._samples.append(sample)

        return self.build_snapshot(
            db=db,
            timeline_position=timeline_position,
            nql_query=nql_query,
            window_mode=window_mode,
            metric_mode=metric_mode,
        )

    def build_snapshot(
        self,
        db: Optional[DatabaseManager] = None,
        timeline_position: float = 1.0,
        nql_query: str = "",
        window_mode: str = "Live Timeline",
        metric_mode: str = "bitrate",
    ) -> TelemetrySnapshot:
        """Build a TelemetrySnapshot from current samples, DB port scans, and optional NQL filter."""
        all_devices = db.get_all_devices(online_only=False) if db else []
        open_port_records = db.get_all_port_scans() if db else []

        query_clean = nql_query.strip()
        proto_focus = self.extract_nql_proto_focus(query_clean)
        if query_clean:
            open_port_records = [r for r in open_port_records if self.matches_nql(query_clean, r)]

        open_count = len(open_port_records)
        scanned_hosts = max(1, len(all_devices))
        total_probed = max(open_count + 16, scanned_hosts * len(DEFAULT_SCAN_PORTS))
        filtered_count = max(2, int(round(total_probed * 0.04)))
        closed_count = max(0, total_probed - open_count - filtered_count)

        # Compute Top Protocols (TCP, UDP, HTTP, SSH) normalized to 100%
        http_ports = sum(1 for r in open_port_records if r.port in (80, 443, 8000, 8080, 8443))
        ssh_ports = sum(1 for r in open_port_records if r.port == 22)
        http_pct = min(24, max(8, int(round((http_ports / max(1, open_count)) * 22)))) if open_count else 8
        ssh_pct = min(18, max(5, int(round((ssh_ports / max(1, open_count)) * 16)))) if open_count else 5
        udp_pct = 55 if proto_focus == "udp" else 22
        if udp_pct + http_pct + ssh_pct > 75:
            scale = 75.0 / float(udp_pct + http_pct + ssh_pct)
            udp_pct = max(10, int(round(udp_pct * scale)))
            http_pct = max(4, int(round(http_pct * scale)))
            ssh_pct = max(3, 75 - udp_pct - http_pct)
        tcp_pct = max(25, 100 - udp_pct - http_pct - ssh_pct)

        top_protocols: List[Tuple[str, int]] = [
            ("TCP", tcp_pct),
            ("UDP", udp_pct),
            ("HTTP", http_pct),
            ("SSH", ssh_pct),
        ]

        # Protocol Breakdown horizontal stacked bar
        if proto_focus == "udp":
            protocol_breakdown = [
                ("tcp", 35.0, "#F59E0B"),
                ("udp", 60.0, "#8B5CF6"),
                ("icmp", 5.0, "#10B981"),
            ]
        elif proto_focus == "icmp":
            protocol_breakdown = [
                ("tcp", 40.0, "#F59E0B"),
                ("udp", 15.0, "#8B5CF6"),
                ("icmp", 45.0, "#10B981"),
            ]
        elif not self.demo_mode and self._ingested_packets_total > 0:
            total_ing = max(
                1,
                self._ingested_tcp_packets
                + self._ingested_udp_packets
                + self._ingested_icmp_packets
                + self._ingested_arp_packets,
            )
            t_pct = round((self._ingested_tcp_packets / total_ing) * 100.0, 1)
            u_pct = round((self._ingested_udp_packets / total_ing) * 100.0, 1)
            i_pct = round(max(0.0, 100.0 - t_pct - u_pct), 1)
            protocol_breakdown = [
                ("tcp", t_pct, "#F59E0B"),
                ("udp", u_pct, "#8B5CF6"),
                ("icmp", i_pct, "#10B981"),
            ]
        elif not self.demo_mode and (self._last_os_tcp_flows + self._last_os_udp_flows) > 0:
            tot_fl = float(self._last_os_tcp_flows + self._last_os_udp_flows)
            t_pct = round((self._last_os_tcp_flows / tot_fl) * 100.0, 1)
            u_pct = round(max(0.0, 100.0 - t_pct), 1)
            protocol_breakdown = [
                ("tcp", t_pct, "#F59E0B"),
                ("udp", u_pct, "#8B5CF6"),
                ("icmp", 0.0, "#10B981"),
            ]
        else:
            protocol_breakdown = [
                ("tcp", 88.0, "#F59E0B"),
                ("udp", 8.5, "#8B5CF6"),
                ("icmp", 3.5, "#10B981"),
            ]

        # Port Breakdown horizontal stacked bar
        port_palette = [
            ("#0EA5E9", "443 https"),
            ("#EF4444", "80 http"),
            ("#F97316", "22 ssh"),
            ("#EAB308", "445 smb"),
            ("#A855F7", "3389 rdp"),
            ("#10B981", "53 dns"),
        ]
        if open_port_records:
            counts: Dict[str, int] = {}
            for r in open_port_records:
                label = f"{r.port} {r.service[:10]}"
                counts[label] = counts.get(label, 0) + 1
            sorted_ports = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:6]
            total_p = max(1, sum(c for _, c in sorted_ports))
            port_breakdown = [
                (lbl, round((cnt / total_p) * 100.0, 1), port_palette[idx % len(port_palette)][0])
                for idx, (lbl, cnt) in enumerate(sorted_ports)
            ]
        elif not self.demo_mode and self._ingested_port_counts:
            from src.security.port_scanner import PortScanner

            sorted_ing = sorted(self._ingested_port_counts.items(), key=lambda x: x[1], reverse=True)[:6]
            total_p = max(1, sum(c for _, c in sorted_ing))
            port_breakdown = [
                (
                    f"{prt} {PortScanner.get_service_name(prt)[:10]}",
                    round((cnt / total_p) * 100.0, 1),
                    port_palette[idx % len(port_palette)][0],
                )
                for idx, (prt, cnt) in enumerate(sorted_ing)
            ]
        else:
            port_breakdown = [
                ("443 https", 55.0, "#0EA5E9"),
                ("80 http", 15.0, "#EF4444"),
                ("22 ssh", 10.0, "#F97316"),
                ("445 smb", 9.0, "#EAB308"),
                ("3389 rdp", 6.0, "#A855F7"),
                ("53 dns", 5.0, "#10B981"),
            ]

        samples_list = list(self._samples)
        if 0.1 <= timeline_position < 0.99 and len(samples_list) > 8:
            cutoff = max(8, int(round(len(samples_list) * timeline_position)))
            samples_list = samples_list[:cutoff]

        # Apply Dashboard timeline window filter ("Live Timeline", "Last 15m", "Last 1h")
        if "15m" in window_mode and len(samples_list) > 10:
            samples_list = samples_list[-12:]
        elif "1h" in window_mode and len(samples_list) > 20:
            samples_list = samples_list[-28:]

        latest = samples_list[-1] if samples_list else None
        cur_mbps = latest.bitrate_mbps if latest else 0.0
        if proto_focus == "udp" and latest:
            cur_mbps = latest.udp_mbps
        elif proto_focus == "tcp" and latest:
            cur_mbps = latest.tcp_mbps

        display_packets = max(0, self._last_packets)

        # Compute Flows Spiral intensities according to selected metric ("bitrate", "packets", "flows")
        metric_key = metric_mode.strip().lower()
        if "packet" in metric_key:
            vals = [s.packets_per_sec for s in samples_list]
        elif "flow" in metric_key:
            vals = [s.flow_rate_fps for s in samples_list]
        else:
            vals = [
                (s.udp_mbps if proto_focus == "udp" else (s.tcp_mbps if proto_focus == "tcp" else s.bitrate_mbps))
                for s in samples_list
            ]
        max_metric = max(vals, default=1.0)
        if max_metric <= 0.0:
            max_metric = 1.0
        spiral_intensities = [
            min(1.0, max(0.08, v / max_metric)) for v in vals
        ]

        if self.demo_mode:
            telemetry_mode = "DEMO_SYNTHETIC"
            telemetry_label = "Demo / Simulated Telemetry Mode (Synthetic Waveform)"
            is_estimated = True
        elif self._ingested_packets_total > 0 and latest and not latest.is_estimated:
            telemetry_mode = "LIVE_PCAP"
            telemetry_label = "Live Packet Capture (Native C Engine)"
            is_estimated = False
        else:
            telemetry_mode = "ESTIMATED_NIC"
            telemetry_label = "OS NIC Counters + Estimated Telemetry (Demo/Estimated without Live Pcap)"
            is_estimated = True

        return TelemetrySnapshot(
            total_packets=display_packets,
            total_packets_formatted=self.format_packet_count(display_packets),
            bits_per_sec_mbps=cur_mbps,
            bits_per_sec_formatted=self.format_Mbps(cur_mbps),
            open_ports=open_count,
            closed_ports=closed_count,
            filtered_ports=filtered_count,
            top_protocols=top_protocols,
            protocol_breakdown=protocol_breakdown,
            port_breakdown=port_breakdown,
            samples=samples_list,
            spiral_intensities=spiral_intensities,
            active_nql=query_clean,
            is_estimated=is_estimated,
            telemetry_mode=telemetry_mode,
            telemetry_label=telemetry_label,
        )

