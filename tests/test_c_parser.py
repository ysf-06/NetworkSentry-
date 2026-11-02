"""Unit tests for Phase 4: Native C Packet Parser Engine and ctypes bridge."""

import struct

from src.native.c_bridge import NativePacketEngine
from src.security.arp_spoof_detector import ARPSpoofDetector


def test_native_c_engine_loads_and_reports_version() -> None:
    """Verify that the C shared library compiles/loads and exposes version info."""
    engine = NativePacketEngine(auto_compile=True)
    assert engine.is_native_loaded is True
    assert "NetworkSentry-NativeEngine" in engine.version()
    assert isinstance(engine.is_pcap_available(), bool)


def test_c_arp_packet_build_and_parse_roundtrip() -> None:
    """Verify building and parsing standard ARP Request and ARP Reply frames in C."""
    engine = NativePacketEngine()

    raw_req = engine.build_arp_frame(
        eth_dst="FF:FF:FF:FF:FF:FF",
        eth_src="00:03:93:11:22:33",
        opcode=1,
        sender_mac="00:03:93:11:22:33",
        sender_ip="192.168.1.42",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.1",
    )
    assert len(raw_req) == 42

    parsed = engine.parse_arp_packet(raw_req)
    assert parsed is not None
    assert parsed.is_valid is True
    assert parsed.opcode == 1
    assert parsed.src_mac == "00:03:93:11:22:33"
    assert parsed.dst_mac == "00:00:00:00:00:00"
    assert parsed.eth_dst_mac == "FF:FF:FF:FF:FF:FF"
    assert parsed.src_ip == "192.168.1.42"
    assert parsed.dst_ip == "192.168.1.1"
    assert parsed.is_gratuitous is False
    assert parsed.mac_mismatch is False
    assert parsed.vlan_id == -1


def test_c_arp_gratuitous_and_mac_mismatch_and_vlan() -> None:
    """Verify Gratuitous ARP, Ethernet/ARP MAC mismatch, and 802.1Q VLAN tag parsing."""
    engine = NativePacketEngine()

    # 1. Gratuitous ARP with spoofed Ethernet source MAC != ARP Sender MAC
    spoof_frame = engine.build_arp_frame(
        eth_dst="FF:FF:FF:FF:FF:FF",
        eth_src="DE:AD:BE:EF:99:99",
        opcode=2,
        sender_mac="50:C7:BF:00:00:01",
        sender_ip="192.168.1.1",
        target_mac="FF:FF:FF:FF:FF:FF",
        target_ip="192.168.1.1",
    )
    pkt = engine.parse_arp_packet(spoof_frame)
    assert pkt is not None
    assert pkt.opcode == 2
    assert pkt.is_gratuitous is True
    assert pkt.mac_mismatch is True
    assert pkt.eth_src_mac == "DE:AD:BE:EF:99:99"
    assert pkt.src_mac == "50:C7:BF:00:00:01"

    # 2. Insert 802.1Q VLAN tag (VLAN ID 100 = 0x0064) at byte 12
    vlan_tag = struct.pack("!HH", 0x8100, 100)
    vlan_frame = spoof_frame[:12] + vlan_tag + spoof_frame[12:]
    vlan_pkt = engine.parse_arp_packet(vlan_frame)
    assert vlan_pkt is not None
    assert vlan_pkt.vlan_id == 100
    assert vlan_pkt.src_ip == "192.168.1.1"

    # 3. Insert 802.1ad QinQ outer S-Tag (0x88A8, VLAN 200) + inner C-Tag (0x8100, VLAN 42)
    qinq_tags = struct.pack("!HHHH", 0x88A8, 200, 0x8100, 42)
    qinq_frame = spoof_frame[:12] + qinq_tags + spoof_frame[12:]
    qinq_pkt = engine.parse_arp_packet(qinq_frame)
    assert qinq_pkt is not None
    assert qinq_pkt.vlan_id == 42
    assert qinq_pkt.mac_mismatch is True


def test_c_ipv4_tcp_packet_parsing_and_malformed_handling() -> None:
    """Verify IPv4 + TCP header parsing and rejection of truncated/corrupt frames."""
    engine = NativePacketEngine()

    # Construct a minimal Ethernet (14B) + IPv4 (20B) + TCP (4B ports) frame
    eth_hdr = bytes.fromhex("50c7bf000001a434d91122330800")
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # Version 4, IHL 5 (20 bytes)
        0,
        40,    # Total length
        1234,
        0,
        64,    # TTL = 64
        6,     # Protocol = TCP (6)
        0,
        bytes([192, 168, 1, 10]),
        bytes([192, 168, 1, 1]),
    )
    tcp_ports = struct.pack("!HH", 54321, 443)
    raw_ipv4 = eth_hdr + ip_hdr + tcp_ports

    ip_pkt = engine.parse_ipv4_packet(raw_ipv4)
    assert ip_pkt is not None
    assert ip_pkt.src_mac == "A4:34:D9:11:22:33"
    assert ip_pkt.dst_mac == "50:C7:BF:00:00:01"
    assert ip_pkt.src_ip == "192.168.1.10"
    assert ip_pkt.dst_ip == "192.168.1.1"
    assert ip_pkt.protocol == 6
    assert ip_pkt.ttl == 64
    assert ip_pkt.src_port == 54321
    assert ip_pkt.dst_port == 443

    # Verify pure-Python fallback when _lib is None
    fallback_engine = NativePacketEngine(lib_path="nonexistent_library.dll", auto_compile=False)
    assert fallback_engine.is_native_loaded is False
    fb_ip = fallback_engine.parse_ipv4_packet(raw_ipv4)
    assert fb_ip is not None
    assert fb_ip.src_port == 54321 and fb_ip.dst_port == 443
    assert fb_ip.tcp_flags == 0

    # Construct full 20-byte TCP header with SYN+ACK (0x12) flags at TCP byte offset 13
    tcp_full = struct.pack("!HHIIBBHHH", 54321, 443, 1, 1, 0x50, 0x12, 65535, 0, 0)
    raw_ipv4_tcp_flags = eth_hdr + ip_hdr + tcp_full
    pkt_flags_c = engine.parse_ipv4_packet(raw_ipv4_tcp_flags)
    pkt_flags_py = fallback_engine.parse_ipv4_packet(raw_ipv4_tcp_flags)
    assert pkt_flags_c is not None and pkt_flags_c.tcp_flags == 0x12
    assert pkt_flags_py is not None and pkt_flags_py.tcp_flags == 0x12

    # Malformed / truncated frames must safely return None
    assert engine.parse_arp_packet(b"") is None
    assert engine.parse_arp_packet(b"\x00" * 15) is None
    assert engine.parse_arp_packet(raw_ipv4) is None  # IPv4 frame is not ARP
    assert engine.parse_ipv4_packet(b"\x00" * 20) is None

    # Invalid ARP opcode (99) must be rejected
    bad_arp = engine.build_arp_frame(
        eth_dst="FF:FF:FF:FF:FF:FF",
        eth_src="00:03:93:11:22:33",
        opcode=99,
        sender_mac="00:03:93:11:22:33",
        sender_ip="192.168.1.42",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.1",
    )
    assert engine.parse_arp_packet(bad_arp) is None
    assert fallback_engine.parse_arp_packet(bad_arp) is None


def test_c_engine_integration_with_arp_spoof_detector() -> None:
    """Verify end-to-end integration from C packet parser to Python ARPSpoofDetector."""
    engine = NativePacketEngine()
    detector = ARPSpoofDetector(lock_gateway_mac=True)
    detector.set_gateway("192.168.1.1", "50:C7:BF:00:00:01")

    attacker_frame = engine.build_arp_frame(
        eth_dst="FF:FF:FF:FF:FF:FF",
        eth_src="AA:BB:CC:66:66:66",
        opcode=2,
        sender_mac="AA:BB:CC:66:66:66",
        sender_ip="192.168.1.1",
        target_mac="FF:FF:FF:FF:FF:FF",
        target_ip="192.168.1.1",
    )
    parsed = engine.parse_arp_packet(attacker_frame)
    assert parsed is not None

    alert = detector.inspect_arp_packet(
        src_mac=parsed.src_mac,
        src_ip=parsed.src_ip,
        dst_mac=parsed.dst_mac,
        dst_ip=parsed.dst_ip,
        opcode=parsed.opcode,
        is_gratuitous=parsed.is_gratuitous,
        eth_src_mac=parsed.eth_src_mac,
        mac_mismatch=parsed.mac_mismatch,
    )
    assert alert is not None
    assert alert.alert_type == "ARP_SPOOFING"
    assert alert.severity == "CRITICAL"
