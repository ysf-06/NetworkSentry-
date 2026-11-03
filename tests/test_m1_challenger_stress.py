"""Adversarial stress tests for Milestone 1: Concurrency, Thread Safety, and Config Persistence.

Challenger 2 Empirical Verification Suite.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from src.core.traffic_monitor import TrafficMonitor
from src.database.db_manager import DatabaseManager
from src.database.models import NetworkInterfaceInfo
from src.gui.main_window import MainWindow
from src.native.pcap_capture import LivePacketCapture
from src.utils.config import ConfigManager


def _get_qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def multi_interfaces() -> list[NetworkInterfaceInfo]:
    return [
        NetworkInterfaceInfo(
            name="eth0",
            ip_address="192.168.1.100",
            netmask="255.255.255.0",
            mac_address="00:11:22:33:44:55",
            gateway_ip="192.168.1.1",
            cidr="192.168.1.0/24",
        ),
        NetworkInterfaceInfo(
            name="wlan0",
            ip_address="10.0.0.50",
            netmask="255.255.255.0",
            mac_address="00:11:22:33:44:66",
            gateway_ip="10.0.0.1",
            cidr="10.0.0.0/24",
        ),
        NetworkInterfaceInfo(
            name="tun0",
            ip_address="172.16.0.2",
            netmask="255.255.255.0",
            mac_address="00:11:22:33:44:77",
            gateway_ip="172.16.0.1",
            cidr="172.16.0.0/24",
        ),
    ]


# =============================================================================
# 1. RAPID TOGGLE STRESS TESTS
# =============================================================================


def test_stress_rapid_toggle_with_consent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stress test: rapidly toggling passive capture checkbox 50 times when consent is granted."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "stress_toggle_consent.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": True,
                "enable_passive_capture": False,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    pcap_starts = 0
    pcap_stops = 0

    def mock_start(self, interface_name=None, interface_ip=None):
        nonlocal pcap_starts
        pcap_starts += 1
        return True

    def mock_stop(self, *args, **kwargs):
        nonlocal pcap_stops
        pcap_stops += 1

    monkeypatch.setattr(TrafficMonitor, "start_live_pcap", mock_start)
    monkeypatch.setattr(TrafficMonitor, "stop_live_pcap", mock_stop)
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        iterations = 50
        for i in range(iterations):
            target_state = (i % 2 == 0)  # True, False, True, False...
            win.chk_passive_capture.setChecked(target_state)

            assert win.chk_passive_capture.isChecked() == target_state
            assert win.cfg.get("security", "enable_passive_capture") == target_state

        # Final state check: after 50 toggles (0 to 49), last i=49 was False
        assert win.chk_passive_capture.isChecked() is False
        assert win.cfg.get("security", "enable_passive_capture") is False
        assert pcap_starts == 25
        assert pcap_stops == 25
    finally:
        win.close()


def test_stress_rapid_toggle_rejected_without_consent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stress test: rapidly attempting to enable passive capture 30 times when consent is denied."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "stress_toggle_reject.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": False,
                "enable_passive_capture": False,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    dialog_calls = 0

    def mock_dialog():
        nonlocal dialog_calls
        dialog_calls += 1
        return False  # User always denies consent

    pcap_starts = 0
    monkeypatch.setattr(TrafficMonitor, "start_live_pcap", lambda *a, **k: pcap_starts + 1)
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        monkeypatch.setattr(win, "_show_consent_dialog", mock_dialog)

        for _ in range(30):
            win.chk_passive_capture.setChecked(True)
            # Must immediately revert to False
            assert win.chk_passive_capture.isChecked() is False
            assert win.cfg.get("security", "enable_passive_capture") is False
            assert win.cfg.get("security", "authorized_network_consent") is False

        assert dialog_calls == 30
        assert pcap_starts == 0
    finally:
        win.close()


# =============================================================================
# 2. INTERFACE SWITCHING STRESS TESTS
# =============================================================================


def test_stress_rapid_interface_switching_under_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, multi_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Stress test: rapidly switching between multiple network interfaces while capture is active."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "stress_iface_switch.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": True,
                "enable_passive_capture": True,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    active_captures = []
    stopped_count = 0

    def mock_start(self, interface_name=None, interface_ip=None):
        active_captures.append((interface_name, interface_ip))
        return True

    def mock_stop(self, *args, **kwargs):
        nonlocal stopped_count
        stopped_count += 1

    monkeypatch.setattr(TrafficMonitor, "start_live_pcap", mock_start)
    monkeypatch.setattr(TrafficMonitor, "stop_live_pcap", mock_stop)
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = multi_interfaces
        active_captures.clear()
        stopped_count = 0

        # Rapidly switch between interfaces 60 times
        for i in range(60):
            target_idx = i % 3
            win._on_interface_changed(target_idx)
            assert win.active_interface == multi_interfaces[target_idx]

        assert stopped_count == 60
        assert len(active_captures) == 60
        # Verify the last switched interface is tun0 (index 59 % 3 == 2)
        assert active_captures[-1] == ("tun0", "172.16.0.2")
    finally:
        win.close()


def test_stress_interface_switch_with_invalid_index(
    tmp_path: Path, multi_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Adversarial test: switching to invalid negative or out-of-bounds indices does not crash or corrupt state."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "stress_invalid_iface.db")
    cfg = ConfigManager(tmp_path / "config.json")

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = multi_interfaces
        initial_iface = win.active_interface

        # Attempt out of bounds
        win._on_interface_changed(-1)
        win._on_interface_changed(999)
        win._on_interface_changed(100)

        # Active interface must remain unchanged
        assert win.active_interface == initial_iface
    finally:
        win.close()


# =============================================================================
# 3. LIVE PACKET CAPTURE THREAD LIFECYCLE & RESOURCE MANAGEMENT
# =============================================================================


def test_stress_live_packet_capture_thread_lifecycle_no_leak() -> None:
    """Stress test: 50 start/stop cycles of LivePacketCapture verify thread terminates and no handles leak."""
    initial_threads = threading.active_count()

    mock_lib = MagicMock()
    mock_lib.pcap_open_live.return_value = 0x12345678
    mock_lib.pcap_close.return_value = None
    mock_lib.pcap_breakloop.return_value = None

    # pcap_next_ex returns 0 (timeout) to allow loop to run and inspect _stop_event
    mock_lib.pcap_next_ex.return_value = 0

    with patch.object(LivePacketCapture, "load_pcap_library", return_value=mock_lib):
        capture = LivePacketCapture()

        for cycle in range(50):
            started = capture.start_capture(
                device_name=r"\Device\NPF_{TEST}",
                packet_callback=lambda raw: None,
            )
            assert started is True
            assert capture.is_capturing is True
            assert capture._thread is not None
            assert capture._thread.is_alive()

            capture.stop_capture()
            assert capture.is_capturing is False
            assert capture._handle is None
            assert not capture._thread.is_alive()

    # Allow tiny cleanup grace
    time.sleep(0.05)
    final_threads = threading.active_count()
    assert final_threads <= initial_threads + 1  # No thread leak


def test_adversarial_pcap_idempotent_double_start_and_stop() -> None:
    """Adversarial test: double start cleans up previous capture, double stop is safe and idempotent."""
    mock_lib = MagicMock()
    mock_lib.pcap_open_live.return_value = 0xAABBCCDD
    mock_lib.pcap_close.return_value = None
    mock_lib.pcap_breakloop.return_value = None
    mock_lib.pcap_next_ex.return_value = 0

    with patch.object(LivePacketCapture, "load_pcap_library", return_value=mock_lib):
        capture = LivePacketCapture()

        # Start 1
        assert capture.start_capture("dev1", lambda r: None) is True
        th1 = capture._thread

        # Start 2 without stopping first
        assert capture.start_capture("dev2", lambda r: None) is True
        th2 = capture._thread
        assert th2 is not None
        assert th1 is not None
        assert not th1.is_alive()  # th1 was stopped cleanly

        # Stop multiple times
        capture.stop_capture()
        capture.stop_capture()
        capture.stop_capture()

        assert capture.is_capturing is False
        assert capture._handle is None


def test_adversarial_pcap_worker_callback_resilience() -> None:
    """Adversarial test: packet_callback raising an unexpected exception does NOT crash the capture worker."""
    import ctypes

    from src.native.pcap_capture import PcapPktHdr

    mock_lib = MagicMock()
    mock_lib.pcap_open_live.return_value = 0x11223344
    mock_lib.pcap_close.return_value = None

    call_count = 0

    def bad_callback(raw: bytes) -> None:
        nonlocal call_count
        call_count += 1
        raise ValueError("Adversarial payload crash!")

    dummy_hdr = PcapPktHdr(0, 0, 60, 60)
    dummy_raw = ctypes.create_string_buffer(b"\x00" * 60)
    dummy_pkt_ptr = ctypes.cast(dummy_raw, ctypes.POINTER(ctypes.c_uint8))

    with patch.object(LivePacketCapture, "load_pcap_library", return_value=mock_lib):
        capture = LivePacketCapture()

        def fake_next_ex(h, hdr_p, pkt_p):
            if call_count < 3:
                hdr_p[0] = ctypes.pointer(dummy_hdr)
                pkt_p[0] = dummy_pkt_ptr
                return 1
            time.sleep(0.01)
            return 0

        mock_lib.pcap_next_ex.side_effect = fake_next_ex

        capture.start_capture("dev", bad_callback)
        time.sleep(0.08)

        assert call_count >= 3
        # Thread should still be alive despite callback exceptions
        assert capture.is_capturing is True

        capture.stop_capture()
        assert capture.is_capturing is False


# =============================================================================
# 4. CONFIG PERSISTENCE & INTEGRITY STRESS TESTS
# =============================================================================


def test_config_persistence_cycle(tmp_path: Path) -> None:
    """Test: enable_passive_capture accurately persists and reloads across fresh instances."""
    cfg_file = tmp_path / "persistence_test.json"
    cfg1 = ConfigManager(cfg_file)

    # Initial default must be False
    assert cfg1.get("security", "enable_passive_capture") is False

    # Set to True and save
    cfg1.set("security", "enable_passive_capture", True)
    cfg1.save()

    # Read back from fresh instance
    cfg2 = ConfigManager(cfg_file)
    assert cfg2.get("security", "enable_passive_capture") is True

    # Read raw JSON file to verify disk integrity
    raw_disk = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert raw_disk["security"]["enable_passive_capture"] is True


def test_adversarial_config_missing_file_fallback(tmp_path: Path) -> None:
    """Adversarial test: missing config file initializes full default schema including enable_passive_capture."""
    nonexistent = tmp_path / "deep" / "nested" / "nonexistent.json"
    cfg = ConfigManager(nonexistent)

    assert cfg.get("security", "enable_passive_capture") is False
    assert cfg.get("security", "authorized_network_consent") is False

    # Saving must create directory and write valid JSON
    cfg.save()
    assert nonexistent.exists()
    reloaded = json.loads(nonexistent.read_text(encoding="utf-8"))
    assert reloaded["security"]["enable_passive_capture"] is False


def test_adversarial_config_corrupted_json_recovery(tmp_path: Path) -> None:
    """Adversarial test: corrupt/truncated JSON is safely handled and healed on next save."""
    corrupt_file = tmp_path / "corrupted_config.json"
    corrupt_file.write_text("{ \"security\": { \"enable_passive_capture\": TRU---corrupt!!!", encoding="utf-8")

    # Loading corrupted config must NOT crash; must fall back to DEFAULT_CONFIG
    cfg = ConfigManager(corrupt_file)
    assert cfg.get("security", "enable_passive_capture") is False
    assert cfg.get("security", "authorized_network_consent") is False

    # Saving must overwrite corrupted file with valid JSON
    cfg.set("security", "enable_passive_capture", True)
    cfg.save()

    valid_json = json.loads(corrupt_file.read_text(encoding="utf-8"))
    assert valid_json["security"]["enable_passive_capture"] is True


def test_adversarial_config_partial_schema_preserves_defaults(tmp_path: Path) -> None:
    """Adversarial test: partial user config missing enable_passive_capture preserves default without wiping existing keys."""
    sparse_file = tmp_path / "sparse_config.json"
    sparse_file.write_text(
        json.dumps({
            "security": {
                "lock_gateway_mac": False,
            }
        }),
        encoding="utf-8",
    )

    cfg = ConfigManager(sparse_file)
    # Existing key loaded
    assert cfg.get("security", "lock_gateway_mac") is False
    # Missing key merged from default
    assert cfg.get("security", "enable_passive_capture") is False
    assert cfg.get("security", "authorized_network_consent") is False


def test_stress_concurrent_config_updates(tmp_path: Path) -> None:
    """Stress test: concurrent threads reading and writing to ConfigManager do not crash or corrupt file."""
    cfg_file = tmp_path / "concurrent_cfg.json"
    cfg = ConfigManager(cfg_file)
    cfg.save()

    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            for i in range(20):
                c = ConfigManager(cfg_file)
                val = (i % 2 == 0)
                c.set("security", "enable_passive_capture", val)
                c.set("security", "thread_marker", thread_id)
                c.save()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)

    assert len(errors) == 0
    # Final file on disk must be valid JSON
    parsed = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert "security" in parsed
    assert "enable_passive_capture" in parsed["security"]


# =============================================================================
# 5. END-TO-END GUI + REAL TRAFFIC MONITOR CONCURRENCY STRESS
# =============================================================================


def test_stress_real_traffic_monitor_gui_rapid_toggle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, multi_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Stress test: Rapidly toggling GUI checkbox with real TrafficMonitor spawning and stopping threads."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "real_tm_toggle.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": True,
                "enable_passive_capture": False,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    mock_lib = MagicMock()
    mock_lib.pcap_open_live.return_value = 0x55667788
    mock_lib.pcap_close.return_value = None
    mock_lib.pcap_breakloop.return_value = None
    mock_lib.pcap_next_ex.return_value = 0

    monkeypatch.setattr(LivePacketCapture, "load_pcap_library", lambda *a: mock_lib)
    monkeypatch.setattr(LivePacketCapture, "is_pcap_available", classmethod(lambda cls: True))
    monkeypatch.setattr(
        LivePacketCapture,
        "find_pcap_device_for_interface",
        classmethod(lambda cls, **kw: r"\Device\NPF_{TEST_DEV}"),
    )
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = multi_interfaces
        win.active_interface = multi_interfaces[0]

        initial_threads = threading.active_count()

        # Rapidly toggle 20 times (10 True, 10 False)
        for i in range(20):
            target = (i % 2 == 0)
            win.chk_passive_capture.setChecked(target)
            if target:
                assert win.traffic_monitor._live_capture is not None
                assert win.traffic_monitor._live_capture.is_capturing is True
            else:
                assert win.traffic_monitor._live_capture is None

        # Ensure final state is stopped
        win.chk_passive_capture.setChecked(False)
        assert win.traffic_monitor._live_capture is None

        time.sleep(0.05)
        # Verify no thread leak
        assert threading.active_count() <= initial_threads + 1
    finally:
        win.close()


def test_stress_real_traffic_monitor_gui_rapid_interface_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, multi_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Stress test: Rapidly switching interfaces with real TrafficMonitor stops active thread and starts new one."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "real_tm_iface_switch.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": True,
                "enable_passive_capture": True,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    mock_lib = MagicMock()
    mock_lib.pcap_open_live.return_value = 0x99887766
    mock_lib.pcap_close.return_value = None
    mock_lib.pcap_breakloop.return_value = None
    mock_lib.pcap_next_ex.return_value = 0

    opened_devices: list[str] = []

    def mock_open_live(dev_bytes, *args):
        opened_devices.append(dev_bytes.decode("utf-8", errors="replace"))
        return 0x99887766

    mock_lib.pcap_open_live.side_effect = mock_open_live

    monkeypatch.setattr(LivePacketCapture, "load_pcap_library", lambda *a: mock_lib)
    monkeypatch.setattr(LivePacketCapture, "is_pcap_available", classmethod(lambda cls: True))
    monkeypatch.setattr(
        LivePacketCapture,
        "find_pcap_device_for_interface",
        classmethod(lambda cls, interface_name=None, **kw: rf"\Device\NPF_{interface_name}"),
    )
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = multi_interfaces
        initial_threads = threading.active_count()

        # Switch across interfaces 21 times
        for i in range(21):
            idx = i % 3
            win._on_interface_changed(idx)
            assert win.traffic_monitor._live_capture is not None
            assert win.traffic_monitor._live_capture.is_capturing is True

        # Check that devices were updated accordingly
        assert len(opened_devices) >= 21
        assert opened_devices[-1] == rf"\Device\NPF_{multi_interfaces[20 % 3].name}"

        # Clean shutdown
        win.traffic_monitor.stop_live_pcap()
        assert win.traffic_monitor._live_capture is None
        time.sleep(0.05)
        assert threading.active_count() <= initial_threads + 1
    finally:
        win.close()


def test_rapid_toggle_without_npcap_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, multi_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Adversarial test: Toggling passive capture when Npcap is absent displays warning and avoids starting capture."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "npcap_missing.db")
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": True,
                "enable_passive_capture": False,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)

    monkeypatch.setattr(LivePacketCapture, "is_pcap_available", classmethod(lambda cls: False))
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = multi_interfaces
        win.active_interface = multi_interfaces[0]

        win.chk_passive_capture.setChecked(True)

        assert win.traffic_monitor._live_capture is None
        assert "Npcap sürücüsü tespit edilemedi" in win.status_bar.currentMessage()
    finally:
        win.close()

