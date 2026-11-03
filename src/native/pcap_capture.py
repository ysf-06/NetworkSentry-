"""Live passive packet capture engine using Npcap (Windows) or libpcap (Linux).

Provides non-blocking wire packet acquisition, safely falls back to honest
OS NIC counters & telemetry mode when Npcap is absent, non-elevated, or restricted.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

from src.utils.logger import setup_logger

logger = setup_logger("LivePcapCapture")


class PcapPktHdr(ctypes.Structure):
    """pcap_pkthdr struct for pcap_next_ex."""

    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
    ]


class PcapAddr(ctypes.Structure):
    pass


class SockAddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_ushort),
        ("sa_data", ctypes.c_char * 14),
    ]


class SockAddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_uint8 * 4),
        ("sin_zero", ctypes.c_char * 8),
    ]


PcapAddr._fields_ = [
    ("next", ctypes.POINTER(PcapAddr)),
    ("addr", ctypes.c_void_p),
    ("netmask", ctypes.c_void_p),
    ("broadaddr", ctypes.c_void_p),
    ("dstaddr", ctypes.c_void_p),
]


class PcapIf(ctypes.Structure):
    pass


PcapIf._fields_ = [
    ("next", ctypes.POINTER(PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(PcapAddr)),
    ("flags", ctypes.c_uint32),
]


class LivePacketCapture:
    """Non-blocking, passive packet capture engine feeding raw frames to TrafficMonitor."""

    _lib: Optional[ctypes.CDLL] = None
    _init_attempted: bool = False
    _load_error: Optional[str] = None

    def __init__(self) -> None:
        self._handle: Optional[ctypes.c_void_p] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_capturing = False
        self._active_device_name: Optional[str] = None
        self._packets_captured = 0
        self._bytes_captured = 0

    @classmethod
    def _is_windows_admin_only_restricted(cls) -> bool:
        """Check whether Windows Npcap is configured in AdminOnly mode while running non-elevated."""
        if sys.platform != "win32":
            return False
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\npcap\Parameters",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "AdminOnly")
                if val == 1:
                    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                    return not is_admin
        except Exception:
            pass
        return False

    @classmethod
    def load_pcap_library(cls) -> Optional[ctypes.CDLL]:
        """Safely locate and load wpcap.dll or libpcap.so."""
        if cls._init_attempted:
            return cls._lib

        cls._init_attempted = True
        system = platform.system().lower()

        if system == "windows":
            if cls._is_windows_admin_only_restricted():
                cls._load_error = "Npcap installed in Admin-Only mode; elevation required for live packet capture"
                logger.info("Npcap detected but host has AdminOnly=1 and process is non-elevated.")
                return None

            dll_dirs = [
                r"C:\Windows\System32\Npcap",
                r"C:\Program Files\Npcap",
                r"C:\Windows\System32",
            ]
            for d in dll_dirs:
                if os.path.exists(d) and hasattr(os, "add_dll_directory"):
                    try:
                        os.add_dll_directory(d)
                    except OSError:
                        pass

            candidates = [
                r"C:\Windows\System32\Npcap\wpcap.dll",
                "wpcap.dll",
            ]
            for cand in candidates:
                try:
                    lib = ctypes.CDLL(cand)
                    cls._bind_signatures(lib)
                    cls._lib = lib
                    cls._load_error = None
                    logger.info("Successfully loaded Npcap library: %s", cand)
                    return lib
                except Exception as exc:
                    cls._load_error = str(exc)
        else:
            candidates = ["libpcap.so.0.8", "libpcap.so.1", "libpcap.so"]
            for cand in candidates:
                try:
                    lib = ctypes.CDLL(cand)
                    cls._bind_signatures(lib)
                    cls._lib = lib
                    cls._load_error = None
                    logger.info("Successfully loaded libpcap library: %s", cand)
                    return lib
                except Exception as exc:
                    cls._load_error = str(exc)

        return None

    @classmethod
    def _bind_signatures(cls, lib: ctypes.CDLL) -> None:
        """Bind ctypes argument and return types for pcap functions."""
        errbuf = ctypes.create_string_buffer(256)
        if hasattr(lib, "pcap_init"):
            try:
                lib.pcap_init.argtypes = [ctypes.c_uint, ctypes.c_char_p]
                lib.pcap_init.restype = ctypes.c_int
                lib.pcap_init(0, errbuf)
            except Exception:
                pass

        if hasattr(lib, "pcap_lib_version"):
            lib.pcap_lib_version.argtypes = []
            lib.pcap_lib_version.restype = ctypes.c_char_p

        lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
        lib.pcap_findalldevs.restype = ctypes.c_int

        lib.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
        lib.pcap_freealldevs.restype = None

        lib.pcap_open_live.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
        ]
        lib.pcap_open_live.restype = ctypes.c_void_p

        lib.pcap_close.argtypes = [ctypes.c_void_p]
        lib.pcap_close.restype = None

        lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(PcapPktHdr)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ]
        lib.pcap_next_ex.restype = ctypes.c_int

        if hasattr(lib, "pcap_breakloop"):
            lib.pcap_breakloop.argtypes = [ctypes.c_void_p]
            lib.pcap_breakloop.restype = None

    @classmethod
    def is_pcap_available(cls) -> bool:
        """Return True if Npcap / libpcap is accessible and can capture packets."""
        return cls.load_pcap_library() is not None

    @classmethod
    def get_pcap_version(cls) -> str:
        """Return driver version string or descriptive fallback."""
        lib = cls.load_pcap_library()
        if lib and hasattr(lib, "pcap_lib_version"):
            try:
                raw = lib.pcap_lib_version()
                if raw:
                    return raw.decode("utf-8", errors="replace")
            except Exception:
                pass
        if cls._load_error:
            return f"Unavailable ({cls._load_error})"
        return "Unavailable (No Npcap/libpcap runtime detected)"

    @classmethod
    def list_pcap_devices(cls, timeout: float = 2.0) -> List[Dict[str, Any]]:
        """Safely list all capture devices with a watchdog timeout to prevent driver deadlocks."""
        lib = cls.load_pcap_library()
        if not lib:
            return []

        results: List[Dict[str, Any]] = []
        errbuf = ctypes.create_string_buffer(256)
        alldevs = ctypes.POINTER(PcapIf)()

        def _worker() -> None:
            try:
                rc = lib.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
                if rc == 0 and alldevs:
                    curr = alldevs
                    while curr:
                        dev = curr.contents
                        name = dev.name.decode("utf-8", errors="replace") if dev.name else ""
                        desc = dev.description.decode("utf-8", errors="replace") if dev.description else ""
                        ips: List[str] = []
                        addr_curr = dev.addresses
                        while addr_curr:
                            try:
                                a = addr_curr.contents
                                if a.addr:
                                    sa = ctypes.cast(a.addr, ctypes.POINTER(SockAddr)).contents
                                    if sa.sa_family == 2:  # AF_INET
                                        sin = ctypes.cast(a.addr, ctypes.POINTER(SockAddrIn)).contents
                                        ip_str = ".".join(str(b) for b in sin.sin_addr)
                                        if ip_str and ip_str != "0.0.0.0":
                                            ips.append(ip_str)
                            except Exception:
                                pass
                            addr_curr = addr_curr.contents.next
                        results.append({"name": name, "description": desc, "ips": ips})
                        curr = dev.next
                    lib.pcap_freealldevs(alldevs)
            except Exception as e:
                logger.debug("pcap_findalldevs exception: %s", e)

        th = threading.Thread(target=_worker, daemon=True)
        th.start()
        th.join(timeout=timeout)
        if th.is_alive():
            logger.warning("pcap_findalldevs timed out after %.1fs (permission wait/deadlock)", timeout)
        return results

    @classmethod
    def find_pcap_device_for_interface(
        cls,
        interface_ip: Optional[str] = None,
        interface_name: Optional[str] = None,
    ) -> Optional[str]:
        """
        Find the Npcap/libpcap device name matching the given interface IP or description.
        Returns device string (e.g., '\\Device\\NPF_{...}' or 'eth0') or None.
        """
        devs = cls.list_pcap_devices()
        if not devs:
            return None

        # 1. Match exact IP address if provided
        if interface_ip:
            target_ip = interface_ip.strip()
            for d in devs:
                dev_ips = d.get("ips", [])
                if target_ip in dev_ips:
                    return d["name"]

        # 2. Match description with interface_name
        if interface_name:
            norm_name = interface_name.lower().strip()
            for d in devs:
                desc = str(d.get("description", "")).lower()
                name = str(d.get("name", "")).lower()
                if norm_name in desc or norm_name in name:
                    return d["name"]

        # 3. Fallback to first non-loopback device
        for d in devs:
            name = str(d.get("name", "")).lower()
            desc = str(d.get("description", "")).lower()
            if "loopback" not in name and "loopback" not in desc:
                return d["name"]

        return devs[0]["name"] if devs else None

    def start_capture(
        self,
        device_name: str,
        packet_callback: Callable[[bytes], Any],
        promiscuous: bool = False,
    ) -> bool:
        """
        Start non-blocking passive wire capture on `device_name`.
        Raw frames are delivered synchronously to `packet_callback(raw_bytes)` on a worker thread.
        """
        lib = self.load_pcap_library()
        if not lib:
            logger.info("Cannot start capture: Npcap/libpcap unavailable.")
            return False

        if self._is_capturing:
            self.stop_capture()

        errbuf = ctypes.create_string_buffer(256)
        dev_bytes = device_name.encode("utf-8")
        # snaplen=65535, promisc=1 if requested, timeout_ms=100
        handle = lib.pcap_open_live(dev_bytes, 65535, 1 if promiscuous else 0, 100, errbuf)
        if not handle:
            err = errbuf.value.decode("utf-8", errors="replace")
            logger.warning("pcap_open_live failed on %s: %s", device_name, err)
            return False

        self._handle = handle
        self._active_device_name = device_name
        self._stop_event.clear()
        self._is_capturing = True
        self._packets_captured = 0
        self._bytes_captured = 0

        def _capture_loop() -> None:
            logger.info("Live packet capture worker started on %s", device_name)
            hdr = ctypes.POINTER(PcapPktHdr)()
            pkt_data = ctypes.POINTER(ctypes.c_uint8)()
            hdr_ptr = ctypes.pointer(hdr)
            pkt_ptr = ctypes.pointer(pkt_data)
            handle = self._handle

            try:
                while not self._stop_event.is_set() and handle:
                    rc = lib.pcap_next_ex(handle, hdr_ptr, pkt_ptr)
                    if rc == 1:
                        if hdr and pkt_data:
                            caplen = int(hdr.contents.caplen)
                            raw = ctypes.string_at(pkt_data, caplen)
                            self._packets_captured += 1
                            self._bytes_captured += caplen
                            try:
                                packet_callback(raw)
                            except Exception as cb_exc:
                                logger.debug("Packet callback exception: %s", cb_exc)
                    elif rc == 0:
                        # 100ms timeout expired with no packets; loop continues
                        continue
                    elif rc in (-1, -2):
                        if rc == -1:
                            logger.warning("pcap_next_ex encountered read error on %s", device_name)
                        break
            finally:
                if handle and lib:
                    try:
                        lib.pcap_close(handle)
                    except Exception:
                        pass
                if self._handle == handle:
                    self._handle = None
                self._is_capturing = False
                logger.info("Live packet capture worker stopped on %s", device_name)

        self._thread = threading.Thread(target=_capture_loop, daemon=True)
        self._thread.start()
        return True

    def stop_capture(self) -> None:
        """Stop active packet capture and release pcap handle."""
        self._stop_event.set()
        lib = self.load_pcap_library()
        handle = self._handle
        if handle and lib and hasattr(lib, "pcap_breakloop"):
            try:
                lib.pcap_breakloop(handle)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if self._handle and lib:
            try:
                lib.pcap_close(self._handle)
            except Exception:
                pass
            self._handle = None
        self._is_capturing = False

    @property
    def is_capturing(self) -> bool:
        return self._is_capturing

    @property
    def active_device(self) -> Optional[str]:
        return self._active_device_name

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "is_capturing": self._is_capturing,
            "packets_captured": self._packets_captured,
            "bytes_captured": self._bytes_captured,
            "device": self._active_device_name,
            "pcap_version": self.get_pcap_version(),
        }
