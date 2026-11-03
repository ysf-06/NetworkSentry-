"""Tests for LivePacketCapture and TrafficMonitor wire capture integration."""

from typing import Any

from src.core.traffic_monitor import TrafficMonitor
from src.native.c_bridge import NativePacketEngine
from src.native.pcap_capture import LivePacketCapture


def test_pcap_capture_availability_and_version() -> None:
    """Verify that is_pcap_available and get_pcap_version return cleanly without hanging."""
    avail = LivePacketCapture.is_pcap_available()
    assert isinstance(avail, bool)
    ver = LivePacketCapture.get_pcap_version()
    assert isinstance(ver, str)
    assert len(ver) > 0


def test_pcap_capture_devices_list_with_watchdog() -> None:
    """Verify list_pcap_devices terminates within its watchdog timeout."""
    devs = LivePacketCapture.list_pcap_devices(timeout=1.0)
    assert isinstance(devs, list)
    for d in devs:
        assert "name" in d
        assert "description" in d


def test_traffic_monitor_wire_packet_ingestion() -> None:
    """Verify that feeding raw frames to ingest_raw_packet switches mode to LIVE_PCAP."""
    engine = NativePacketEngine(auto_compile=True)
    mon = TrafficMonitor(max_samples=20, demo_mode=False, c_engine=engine)

    # Initially in ESTIMATED_NIC mode
    snap0 = mon.record_tick(db=None)
    assert snap0.telemetry_mode == "ESTIMATED_NIC"
    assert snap0.is_estimated is True

    # Craft a 42-byte raw ARP frame
    raw_arp = engine.build_arp_frame(
        eth_dst="FF:FF:FF:FF:FF:FF",
        eth_src="50:C7:BF:00:00:01",
        opcode=1,
        sender_mac="50:C7:BF:00:00:01",
        sender_ip="192.168.1.1",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.150",
    )
    ok_arp = mon.ingest_raw_packet(raw_arp)
    assert ok_arp is True

    # Craft a synthetic IPv4 TCP packet (14-byte Ethernet + 20-byte IP + 20-byte TCP)
    # Ethernet header: dst MAC (6), src MAC (6), ethertype 0x0800 (2)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x50\xC7\xBF\x00\x00\x01\x08\x00"
    # IPv4 header: ver/ihl=0x45, tos=0, total_len=40, id=1, flags/frag=0x4000, ttl=64, proto=6 (TCP), csum=0, src=192.168.1.50, dst=192.168.1.1
    ip_hdr = b"\x45\x00\x00\x28\x00\x01\x40\x00\x40\x06\x00\x00\xC0\xA8\x01\x32\xC0\xA8\x01\x01"
    # TCP header: src_port=54321, dst_port=443, seq=1, ack=1, doff/flags=0x5012 (SYN+ACK), win=65535, csum=0, urg=0
    tcp_hdr = b"\xD4\x31\x01\xBB\x00\x00\x00\x01\x00\x00\x00\x01\x50\x12\xFF\xFF\x00\x00\x00\x00"
    raw_ip = eth_hdr + ip_hdr + tcp_hdr

    ok_ip = mon.ingest_raw_packet(raw_ip)
    assert ok_ip is True

    # Tick monitor with live ingested packets -> switches to LIVE_PCAP
    snap1 = mon.record_tick(db=None)

    assert snap1.telemetry_mode == "LIVE_PCAP"
    assert snap1.is_estimated is False
    assert snap1.bits_per_sec_mbps >= 0.0


def test_traffic_monitor_live_pcap_start_stop() -> None:
    """Verify start_live_pcap and stop_live_pcap handle calls safely."""
    mon = TrafficMonitor(max_samples=20, demo_mode=False)
    # Even if Npcap is not allowed or unavailable, start_live_pcap returns bool safely
    started = mon.start_live_pcap(interface_name="Loopback", interface_ip="127.0.0.1")
    assert isinstance(started, bool)
    mon.stop_live_pcap()
    assert mon._live_capture is None


def test_find_pcap_device_for_interface_matching(monkeypatch) -> None:
    """Verify find_pcap_device_for_interface prioritizes IP match, then name, then non-loopback fallback."""
    fake_devs = [
        {"name": r"\Device\NPF_{1111-2222}", "description": "Adapter One", "ips": ["10.0.0.5"]},
        {"name": r"\Device\NPF_{3333-4444}", "description": "Intel Wi-Fi 6", "ips": ["192.168.1.100"]},
        {"name": r"\Device\NPF_Loopback", "description": "Npcap Loopback Adapter", "ips": ["127.0.0.1"]},
    ]
    monkeypatch.setattr(LivePacketCapture, "list_pcap_devices", classmethod(lambda cls, timeout=2.0: fake_devs))

    # 1. Exact IP match
    dev = LivePacketCapture.find_pcap_device_for_interface(interface_ip="192.168.1.100", interface_name="Ethernet")
    assert dev == r"\Device\NPF_{3333-4444}"

    # 2. Name / description match when IP not found
    dev_name = LivePacketCapture.find_pcap_device_for_interface(interface_ip="172.16.0.1", interface_name="Wi-Fi")
    assert dev_name == r"\Device\NPF_{3333-4444}"

    # 3. Non-loopback fallback
    dev_fallback = LivePacketCapture.find_pcap_device_for_interface(interface_ip="172.16.0.1", interface_name="NonExistent")
    assert dev_fallback == r"\Device\NPF_{1111-2222}"

    # 4. Empty devices returns None
    monkeypatch.setattr(LivePacketCapture, "list_pcap_devices", classmethod(lambda cls, timeout=2.0: []))
    assert LivePacketCapture.find_pcap_device_for_interface(interface_ip="192.168.1.1") is None


def test_live_packet_capture_lifecycle_with_mock_library(monkeypatch) -> None:
    """Verify LivePacketCapture start_capture loop and thread-safe stop_capture."""
    import ctypes

    from src.native.pcap_capture import PcapPktHdr

    received_packets: list[bytes] = []
    persistent_refs: list[Any] = []

    class MockLib:
        def __init__(self):
            self.closed_handles = []
            self.breakloop_called = False

        def pcap_open_live(self, dev, snaplen, promisc, timeout_ms, errbuf):
            return ctypes.c_void_p(0x12345678)

        def pcap_next_ex(self, handle, hdr_ptr, pkt_ptr):
            if len(received_packets) < 3:
                h = PcapPktHdr(0, 0, 14, 14)
                fake_frame = (ctypes.c_uint8 * 14)(*b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00")
                persistent_refs.extend([h, fake_frame])
                hdr_ptr[0] = ctypes.pointer(h)
                pkt_ptr[0] = ctypes.cast(fake_frame, ctypes.POINTER(ctypes.c_uint8))
                return 1
            return 0  # timeout

        def pcap_breakloop(self, handle):
            self.breakloop_called = True

        def pcap_close(self, handle):
            if handle is None:
                raise ValueError("pcap_close called on NULL handle!")
            self.closed_handles.append(handle)

    mock_lib = MockLib()
    monkeypatch.setattr(LivePacketCapture, "load_pcap_library", classmethod(lambda cls: mock_lib))

    capture = LivePacketCapture()
    started = capture.start_capture(
        device_name=r"\Device\NPF_{TEST}",
        packet_callback=lambda raw: received_packets.append(raw),
    )
    assert started is True
    assert capture.is_capturing is True

    import time
    time.sleep(0.15)
    assert len(received_packets) >= 3

    stats = capture.stats
    assert stats["packets_captured"] >= 3
    assert stats["bytes_captured"] >= 42

    capture.stop_capture()
    assert capture.is_capturing is False
    assert len(mock_lib.closed_handles) == 1
    # Calling stop_capture again should be a clean no-op without re-closing or throwing
    capture.stop_capture()
    assert len(mock_lib.closed_handles) == 1

