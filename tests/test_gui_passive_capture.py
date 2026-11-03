"""Unit tests for GUI passive packet capture consent gating and UI controls."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from src.core.traffic_monitor import TrafficMonitor
from src.database.db_manager import DatabaseManager
from src.database.models import NetworkInterfaceInfo
from src.gui.main_window import MainWindow
from src.utils.config import ConfigManager


def _get_qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def dummy_interfaces() -> list[NetworkInterfaceInfo]:
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
    ]


def test_gui_startup_no_pcap_when_no_consent(tmp_path: Path) -> None:
    """MainWindow must not start live packet capture on startup when consent is False."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_no_consent.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        assert win.traffic_monitor._live_capture is None
        assert win.chk_passive_capture.isChecked() is False
    finally:
        win.close()


def test_gui_startup_no_pcap_when_consent_true_but_passive_false(tmp_path: Path) -> None:
    """MainWindow must not start live packet capture if consent is True but enable_passive_capture is False."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_consent_only.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        assert win.traffic_monitor._live_capture is None
        assert win.chk_passive_capture.isChecked() is False
    finally:
        win.close()


def test_gui_startup_starts_pcap_when_both_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """MainWindow starts live packet capture if both consent and enable_passive_capture are True."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_both_enabled.db")
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

    mock_start = MagicMock(return_value=True)
    monkeypatch.setattr(TrafficMonitor, "start_live_pcap", mock_start)
    monkeypatch.setattr(MainWindow, "_setup_timers", lambda self: None)

    win = MainWindow(config=cfg, db=db)
    try:
        # Check initial state of the checkbox
        assert win.chk_passive_capture.isChecked() is True
        mock_start.assert_called_once()
    finally:
        win.close()


def test_gui_passive_capture_toggle_rejected_without_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checking passive capture without consent prompts dialog; rejecting unchecks box and does not start pcap."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_reject.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        # Mock consent dialog to return False (user rejects)
        mock_dialog = MagicMock(return_value=False)
        monkeypatch.setattr(win, "_show_consent_dialog", mock_dialog)

        mock_pcap_start = MagicMock(return_value=True)
        monkeypatch.setattr(win.traffic_monitor, "start_live_pcap", mock_pcap_start)

        # User attempts to enable passive capture
        win.chk_passive_capture.setChecked(True)

        mock_dialog.assert_called_once()
        assert win.chk_passive_capture.isChecked() is False
        assert win.cfg.get("security", "enable_passive_capture", False) is False
        mock_pcap_start.assert_not_called()
    finally:
        win.close()


def test_gui_passive_capture_toggle_accepted_without_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checking passive capture without consent prompts dialog; accepting enables capture and saves config."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_accept.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        def fake_consent_dialog() -> bool:
            win.cfg.set("security", "authorized_network_consent", True)
            return True

        monkeypatch.setattr(win, "_show_consent_dialog", fake_consent_dialog)

        mock_pcap_start = MagicMock(return_value=True)
        monkeypatch.setattr(win.traffic_monitor, "start_live_pcap", mock_pcap_start)

        win.chk_passive_capture.setChecked(True)

        assert win.chk_passive_capture.isChecked() is True
        assert win.cfg.get("security", "enable_passive_capture") is True
        assert win.cfg.get("security", "authorized_network_consent") is True
        mock_pcap_start.assert_called_once()
    finally:
        win.close()


def test_gui_passive_capture_toggle_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unchecking passive capture stops live pcap and updates config."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_toggle_off.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        mock_stop = MagicMock()
        monkeypatch.setattr(win.traffic_monitor, "stop_live_pcap", mock_stop)

        win.chk_passive_capture.setChecked(False)

        assert win.chk_passive_capture.isChecked() is False
        assert win.cfg.get("security", "enable_passive_capture") is False
        mock_stop.assert_called_once()
    finally:
        win.close()


def test_gui_interface_switch_stops_and_conditionally_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dummy_interfaces: list[NetworkInterfaceInfo]
) -> None:
    """Switching interface stops active capture and restarts on new adapter only if permitted."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / "gui_iface_switch.db")
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

    win = MainWindow(config=cfg, db=db)
    try:
        win.interfaces = dummy_interfaces
        mock_stop = MagicMock()
        mock_start = MagicMock(return_value=True)
        monkeypatch.setattr(win.traffic_monitor, "stop_live_pcap", mock_stop)
        monkeypatch.setattr(win.traffic_monitor, "start_live_pcap", mock_start)

        # Case 1: Consent False, passive False -> switch interface
        win._on_interface_changed(1)
        mock_stop.assert_called_once()
        mock_start.assert_not_called()
        assert win.active_interface == dummy_interfaces[1]

        # Case 2: Consent True, passive True -> switch interface
        win.cfg.set("security", "authorized_network_consent", True)
        win.cfg.set("security", "enable_passive_capture", True)
        mock_stop.reset_mock()
        mock_start.reset_mock()

        win._on_interface_changed(0)
        mock_stop.assert_called_once()
        mock_start.assert_called_once_with(
            interface_name=dummy_interfaces[0].name,
            interface_ip=dummy_interfaces[0].ip_address,
        )
        assert win.active_interface == dummy_interfaces[0]
    finally:
        win.close()


@pytest.mark.parametrize("falsy_val", ["false", "False", "0", "no", "off", "disabled"])
def test_gui_startup_string_falsy_consent_does_not_start_pcap(tmp_path: Path, falsy_val: str) -> None:
    """MainWindow must not start pcap if consent is string falsy even if enable_passive_capture is True."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / f"gui_falsy_{hash(falsy_val)}.db")
    cfg_file = tmp_path / f"config_{hash(falsy_val)}.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": falsy_val,
                "enable_passive_capture": True,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)
    win = MainWindow(config=cfg, db=db)
    try:
        assert win.traffic_monitor._live_capture is None
        assert win.chk_passive_capture.isChecked() is False
        assert win.cfg.has_authorized_consent() is False
    finally:
        win.close()


@pytest.mark.parametrize("falsy_val", ["false", "0", "no"])
def test_gui_scan_string_falsy_consent_triggers_dialog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, falsy_val: str
) -> None:
    """MainWindow start_network_scan must trigger consent dialog when config consent is string falsy."""
    _get_qapp()
    db = DatabaseManager(db_path=tmp_path / f"gui_scan_falsy_{hash(falsy_val)}.db")
    cfg_file = tmp_path / f"config_{hash(falsy_val)}.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": falsy_val,
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)
    win = MainWindow(config=cfg, db=db)
    try:
        mock_dialog = MagicMock(return_value=False)
        monkeypatch.setattr(win, "_show_consent_dialog", mock_dialog)
        win.start_network_scan()
        assert mock_dialog.called
    finally:
        win.close()

