"""Python ctypes bridge for the Native C Packet Parser Engine (packet_parser.dll / .so)."""

import ctypes
import os
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.utils.logger import setup_logger
from src.utils.oui_lookup import OUILookup

logger = setup_logger("NativeCBridge")


def _resolve_native_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = Path(getattr(sys, "_MEIPASS"))
        for rel in (Path("src") / "native", Path(".")):
            if (meipass / rel / "packet_parser.dll").exists() or (meipass / rel / "packet_parser.so").exists():
                return meipass / rel
    return Path(__file__).resolve().parent


NATIVE_DIR = _resolve_native_dir()


class CStructParsedArpPacket(ctypes.Structure):
    """Mirrors `ParsedArpPacket` in `src/native/include/packet_parser.h`."""

    _fields_ = [
        ("src_mac", ctypes.c_char * 18),
        ("dst_mac", ctypes.c_char * 18),
        ("eth_src_mac", ctypes.c_char * 18),
        ("eth_dst_mac", ctypes.c_char * 18),
        ("src_ip", ctypes.c_char * 16),
        ("dst_ip", ctypes.c_char * 16),
        ("opcode", ctypes.c_int),
        ("is_gratuitous", ctypes.c_int),
        ("mac_mismatch", ctypes.c_int),
        ("vlan_id", ctypes.c_int),
        ("is_valid", ctypes.c_int),
    ]


class CStructParsedIpPacket(ctypes.Structure):
    """Mirrors `ParsedIpPacket` in `src/native/include/packet_parser.h`."""

    _fields_ = [
        ("src_mac", ctypes.c_char * 18),
        ("dst_mac", ctypes.c_char * 18),
        ("src_ip", ctypes.c_char * 16),
        ("dst_ip", ctypes.c_char * 16),
        ("protocol", ctypes.c_int),
        ("src_port", ctypes.c_int),
        ("dst_port", ctypes.c_int),
        ("ttl", ctypes.c_int),
        ("total_length", ctypes.c_int),
        ("is_valid", ctypes.c_int),
    ]


@dataclass
class ArpPacketInfo:
    """Python representation of a parsed ARP frame."""

    src_mac: str
    dst_mac: str
    eth_src_mac: str
    eth_dst_mac: str
    src_ip: str
    dst_ip: str
    opcode: int
    is_gratuitous: bool
    mac_mismatch: bool
    vlan_id: int
    is_valid: bool = True


@dataclass
class IpPacketInfo:
    """Python representation of a parsed IPv4 frame."""

    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int
    dst_port: int
    ttl: int
    total_length: int
    is_valid: bool = True


class NativePacketEngine:
    """Loads and wraps the native C packet parser shared library via ctypes."""

    def __init__(self, lib_path: Optional[str | Path] = None, auto_compile: bool = True) -> None:
        self._lib: Optional[ctypes.CDLL] = None
        self.lib_path = Path(lib_path) if lib_path else self._default_lib_path()
        self._load_or_build(auto_compile=auto_compile)

    @staticmethod
    def _default_lib_path() -> Path:
        ext = "dll" if platform.system().lower() == "windows" else "so"
        return NATIVE_DIR / f"packet_parser.{ext}"

    @staticmethod
    def _find_gcc() -> Optional[str]:
        gcc_in_path = shutil.which("gcc")
        if gcc_in_path:
            return gcc_in_path
        for candidate in (
            r"C:\msys64\ucrt64\bin\gcc.exe",
            r"C:\msys64\mingw64\bin\gcc.exe",
            r"C:\mingw64\bin\gcc.exe",
        ):
            if os.path.exists(candidate):
                return candidate
        return None

    def compile_shared_library(self) -> bool:
        """Compile `packet_parser.c` into a shared library using GCC."""
        gcc_bin = self._find_gcc()
        if not gcc_bin:
            logger.warning("GCC compiler not found; cannot auto-compile packet_parser.")
            return False

        c_src = NATIVE_DIR / "src" / "packet_parser.c"
        inc_dir = NATIVE_DIR / "include"
        if not c_src.exists():
            return False

        cmd = [
            gcc_bin,
            "-O3",
            "-Wall",
            "-Wextra",
            "-shared",
            "-DBUILDING_PACKET_PARSER",
            str(c_src),
            f"-I{inc_dir}",
            "-o",
            str(self.lib_path),
        ]
        if platform.system().lower() != "windows":
            cmd.insert(4, "-fPIC")
            cmd.append("-ldl")

        env = os.environ.copy()
        gcc_dir = str(Path(gcc_bin).parent)
        env["PATH"] = f"{gcc_dir}{os.pathsep}{env.get('PATH', '')}"

        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
                creationflags=creationflags,
            )
            if proc.returncode == 0 and self.lib_path.exists():
                logger.info("Successfully compiled native C engine: %s", self.lib_path)
                return True
            logger.error("GCC build failed: %s", proc.stderr)
        except Exception as exc:
            logger.error("Exception compiling native C engine: %s", exc)
        return False

    def _load_or_build(self, auto_compile: bool) -> None:
        if not self.lib_path.exists() and auto_compile:
            self.compile_shared_library()

        if not self.lib_path.exists():
            return

        try:
            # On Windows, ensure MinGW runtime DLL directory is searchable if needed
            if hasattr(os, "add_dll_directory"):
                gcc_bin = self._find_gcc()
                if gcc_bin:
                    try:
                        os.add_dll_directory(str(Path(gcc_bin).parent))
                    except OSError:
                        pass

            lib = ctypes.CDLL(str(self.lib_path))

            lib.parse_arp_packet.argtypes = [
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(CStructParsedArpPacket),
            ]
            lib.parse_arp_packet.restype = ctypes.c_int

            lib.parse_ipv4_packet.argtypes = [
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
                ctypes.POINTER(CStructParsedIpPacket),
            ]
            lib.parse_ipv4_packet.restype = ctypes.c_int

            lib.build_arp_frame.argtypes = [
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_uint16,
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.c_size_t,
            ]
            lib.build_arp_frame.restype = ctypes.c_int

            lib.is_pcap_available.argtypes = []
            lib.is_pcap_available.restype = ctypes.c_int

            lib.packet_engine_version.argtypes = []
            lib.packet_engine_version.restype = ctypes.c_char_p

            self._lib = lib
        except Exception as exc:
            logger.warning("Failed to load native library %s: %s", self.lib_path, exc)
            self._lib = None

    @property
    def is_native_loaded(self) -> bool:
        """Return True if the compiled C shared library is loaded and active."""
        return self._lib is not None

    def version(self) -> str:
        """Return the engine version identifier."""
        if self._lib is not None:
            raw = self._lib.packet_engine_version()
            if raw:
                return raw.decode("utf-8", errors="replace")
        return "NetworkSentry-PythonFallback/1.0.0"

    def is_pcap_available(self) -> bool:
        """Return True if Npcap / libpcap is installed on the host."""
        if self._lib is not None:
            return bool(self._lib.is_pcap_available() == 1)
        return False

    @staticmethod
    def _mac_to_bytes(mac: str) -> bytes:
        norm = OUILookup.normalize_mac(mac)
        if not norm:
            if mac.strip() == "00:00:00:00:00:00":
                return b"\x00" * 6
            raise ValueError(f"Invalid MAC address: {mac}")
        return bytes(int(part, 16) for part in norm.split(":"))

    def build_arp_frame(
        self,
        eth_dst: str,
        eth_src: str,
        opcode: int,
        sender_mac: str,
        sender_ip: str,
        target_mac: str,
        target_ip: str,
    ) -> bytes:
        """Construct a 42-byte raw Ethernet + IPv4 ARP packet using the C engine."""
        eth_dst_b = self._mac_to_bytes(eth_dst)
        eth_src_b = self._mac_to_bytes(eth_src)
        sha_b = self._mac_to_bytes(sender_mac)
        tha_b = self._mac_to_bytes(target_mac)
        spa_b = socket.inet_aton(sender_ip)
        tpa_b = socket.inet_aton(target_ip)

        if self._lib is not None:
            out_buf = (ctypes.c_uint8 * 42)()
            rc = self._lib.build_arp_frame(
                (ctypes.c_uint8 * 6).from_buffer_copy(eth_dst_b),
                (ctypes.c_uint8 * 6).from_buffer_copy(eth_src_b),
                ctypes.c_uint16(opcode),
                (ctypes.c_uint8 * 6).from_buffer_copy(sha_b),
                (ctypes.c_uint8 * 4).from_buffer_copy(spa_b),
                (ctypes.c_uint8 * 6).from_buffer_copy(tha_b),
                (ctypes.c_uint8 * 4).from_buffer_copy(tpa_b),
                out_buf,
                42,
            )
            if rc < 0:
                raise ValueError(f"C build_arp_frame failed with code {rc}")
            return bytes(out_buf)

        # Fallback builder if C library is unavailable
        import struct

        eth_hdr = eth_dst_b + eth_src_b + b"\x08\x06"
        arp_hdr = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
        return eth_hdr + arp_hdr + sha_b + spa_b + tha_b + tpa_b

    def parse_arp_packet(self, raw_bytes: bytes) -> Optional[ArpPacketInfo]:
        """Parse raw Ethernet frame bytes into `ArpPacketInfo` via C struct zero-copy."""
        if not raw_bytes or len(raw_bytes) < 42:
            return None

        if self._lib is not None:
            c_pkt = CStructParsedArpPacket()
            buf = (ctypes.c_uint8 * len(raw_bytes)).from_buffer_copy(raw_bytes)
            rc = self._lib.parse_arp_packet(buf, len(raw_bytes), ctypes.byref(c_pkt))
            if rc != 0 or c_pkt.is_valid != 1:
                return None
            return ArpPacketInfo(
                src_mac=c_pkt.src_mac.decode("ascii"),
                dst_mac=c_pkt.dst_mac.decode("ascii"),
                eth_src_mac=c_pkt.eth_src_mac.decode("ascii"),
                eth_dst_mac=c_pkt.eth_dst_mac.decode("ascii"),
                src_ip=c_pkt.src_ip.decode("ascii"),
                dst_ip=c_pkt.dst_ip.decode("ascii"),
                opcode=int(c_pkt.opcode),
                is_gratuitous=bool(c_pkt.is_gratuitous),
                mac_mismatch=bool(c_pkt.mac_mismatch),
                vlan_id=int(c_pkt.vlan_id),
                is_valid=True,
            )
        # Fallback pure-Python parser when native shared library is unavailable
        import struct

        eth_dst = ":".join(f"{b:02X}" for b in raw_bytes[0:6])
        eth_src = ":".join(f"{b:02X}" for b in raw_bytes[6:12])
        ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
        offset = 14
        vlan_id = -1
        vlan_tags = 0
        while ethertype in (0x8100, 0x88A8) and vlan_tags < 2:
            if len(raw_bytes) < offset + 4 + 28:
                return None
            tci, ethertype = struct.unpack("!HH", raw_bytes[offset : offset + 4])
            vlan_id = tci & 0x0FFF
            offset += 4
            vlan_tags += 1

        if ethertype != 0x0806 or len(raw_bytes) < offset + 28:
            return None

        htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", raw_bytes[offset : offset + 8])
        if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or opcode not in (1, 2):
            return None

        sha = raw_bytes[offset + 8 : offset + 14]
        spa = raw_bytes[offset + 14 : offset + 18]
        tha = raw_bytes[offset + 18 : offset + 24]
        tpa = raw_bytes[offset + 24 : offset + 28]
        src_mac = ":".join(f"{b:02X}" for b in sha)
        dst_mac = ":".join(f"{b:02X}" for b in tha)
        src_ip = socket.inet_ntoa(spa)
        dst_ip = socket.inet_ntoa(tpa)
        return ArpPacketInfo(
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_src_mac=eth_src,
            eth_dst_mac=eth_dst,
            src_ip=src_ip,
            dst_ip=dst_ip,
            opcode=opcode,
            is_gratuitous=(spa == tpa),
            mac_mismatch=(eth_src != src_mac),
            vlan_id=vlan_id,
            is_valid=True,
        )

    def parse_ipv4_packet(self, raw_bytes: bytes) -> Optional[IpPacketInfo]:
        """Parse raw Ethernet + IPv4 frame bytes into `IpPacketInfo` via C struct."""
        if not raw_bytes or len(raw_bytes) < 34:
            return None

        if self._lib is not None:
            c_pkt = CStructParsedIpPacket()
            buf = (ctypes.c_uint8 * len(raw_bytes)).from_buffer_copy(raw_bytes)
            rc = self._lib.parse_ipv4_packet(buf, len(raw_bytes), ctypes.byref(c_pkt))
            if rc != 0 or c_pkt.is_valid != 1:
                return None
            return IpPacketInfo(
                src_mac=c_pkt.src_mac.decode("ascii"),
                dst_mac=c_pkt.dst_mac.decode("ascii"),
                src_ip=c_pkt.src_ip.decode("ascii"),
                dst_ip=c_pkt.dst_ip.decode("ascii"),
                protocol=int(c_pkt.protocol),
                src_port=int(c_pkt.src_port),
                dst_port=int(c_pkt.dst_port),
                ttl=int(c_pkt.ttl),
                total_length=int(c_pkt.total_length),
                is_valid=True,
            )

        # Fallback pure-Python IPv4 parser
        import struct

        dst_mac = ":".join(f"{b:02X}" for b in raw_bytes[0:6])
        src_mac = ":".join(f"{b:02X}" for b in raw_bytes[6:12])
        ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
        offset = 14
        vlan_tags = 0
        while ethertype in (0x8100, 0x88A8) and vlan_tags < 2:
            if len(raw_bytes) < offset + 4 + 20:
                return None
            _, ethertype = struct.unpack("!HH", raw_bytes[offset : offset + 4])
            offset += 4
            vlan_tags += 1

        if ethertype != 0x0800 or len(raw_bytes) < offset + 20:
            return None

        ip_hdr = raw_bytes[offset:]
        version = (ip_hdr[0] >> 4) & 0x0F
        ihl = (ip_hdr[0] & 0x0F) * 4
        total_len = struct.unpack("!H", ip_hdr[2:4])[0]
        if version != 4 or ihl < 20 or len(raw_bytes) < offset + ihl or total_len < ihl:
            return None

        ttl = ip_hdr[8]
        protocol = ip_hdr[9]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])
        src_port, dst_port = 0, 0
        if protocol in (6, 17) and len(raw_bytes) >= offset + ihl + 4:
            src_port, dst_port = struct.unpack("!HH", ip_hdr[ihl : ihl + 4])

        return IpPacketInfo(
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            total_length=total_len,
            is_valid=True,
        )
