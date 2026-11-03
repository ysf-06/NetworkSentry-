"""Tests for CLI network scan user consent and authorization gating."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import main
from main import run_cli_scan
from src.core.arp_scanner import ARPScanner, DiscoveryResult
from src.core.interface_detector import InterfaceDetector
from src.database.models import DeviceRecord, NetworkInterfaceInfo
from src.security.port_scanner import PortScanner
from src.utils.config import ConfigManager, coerce_bool, is_consent_granted, to_bool


@pytest.fixture
def dummy_interface() -> NetworkInterfaceInfo:
    return NetworkInterfaceInfo(
        name="TestEth0",
        ip_address="192.168.1.100",
        netmask="255.255.255.0",
        mac_address="00:11:22:33:44:55",
        gateway_ip="192.168.1.1",
        cidr="192.168.1.0/24",
    )


def test_cli_scan_without_consent_returns_1_and_does_not_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_cli_scan must immediately return 1 without scanning when consent is False."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": False,
            }
        }),
        encoding="utf-8",
    )

    mock_scan = MagicMock()
    monkeypatch.setattr(ARPScanner, "scan_and_sync", mock_scan)

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=False,
    )

    assert exit_code == 1
    mock_scan.assert_not_called()

    captured = capsys.readouterr()
    assert "NOTICE: Authorized Networks Only" in captured.out
    assert "Scanning subnet" not in captured.out


def test_cli_scan_with_config_consent_proceeds(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    dummy_interface: NetworkInterfaceInfo,
) -> None:
    """run_cli_scan proceeds and executes scan when config has authorized_network_consent=True."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({
            "database": {"path": str(tmp_path / "cli_test.db")},
            "security": {
                "authorized_network_consent": True,
            },
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr(InterfaceDetector, "get_active_interface", lambda pref=None: dummy_interface)

    mock_scan = MagicMock(return_value=DiscoveryResult(
        session_id=1,
        interface=dummy_interface,
        discovered_devices=[
            DeviceRecord(ip="192.168.1.1", mac="00:aa:bb:cc:dd:ee", hostname="gw", vendor="RouterVendor")
        ],
        ip_to_macs={"192.168.1.1": {"00:aa:bb:cc:dd:ee"}},
        duration_seconds=0.1,
    ))
    monkeypatch.setattr(ARPScanner, "scan_and_sync", mock_scan)
    monkeypatch.setattr(PortScanner, "scan_host", MagicMock(return_value=[]))

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=False,
    )

    assert exit_code == 0
    mock_scan.assert_called_once()
    captured = capsys.readouterr()
    assert "NOTICE: Authorized Networks Only" not in captured.out
    assert "Scanning subnet" in captured.out


def test_cli_scan_with_cli_flag_proceeds(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    dummy_interface: NetworkInterfaceInfo,
) -> None:
    """run_cli_scan proceeds when consent_granted=True even if config has consent=False."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({
            "database": {"path": str(tmp_path / "cli_test_flag.db")},
            "security": {
                "authorized_network_consent": False,
            },
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr(InterfaceDetector, "get_active_interface", lambda pref=None: dummy_interface)

    mock_scan = MagicMock(return_value=DiscoveryResult(
        session_id=2,
        interface=dummy_interface,
        discovered_devices=[],
        ip_to_macs={},
        duration_seconds=0.05,
    ))
    monkeypatch.setattr(ARPScanner, "scan_and_sync", mock_scan)

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=True,
    )

    assert exit_code == 0
    mock_scan.assert_called_once()
    captured = capsys.readouterr()
    assert "NOTICE: Authorized Networks Only" not in captured.out
    assert "Scanning subnet" in captured.out


def test_cli_scan_no_active_interface(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_cli_scan returns 1 if no network interface is found after consent is verified."""
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps({
            "database": {"path": str(tmp_path / "cli_test_no_iface.db")},
            "security": {
                "authorized_network_consent": True,
            },
        }),
        encoding="utf-8",
    )

    monkeypatch.setattr(InterfaceDetector, "get_active_interface", lambda pref=None: None)

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=False,
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "No active IPv4 network interface detected" in captured.out


def test_main_cli_yes_argument_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that CLI --yes and -y flags parse correctly and pass consent_granted=True."""
    mock_run_scan = MagicMock(return_value=0)
    monkeypatch.setattr(main, "run_cli_scan", mock_run_scan)
    monkeypatch.setattr(main, "_ensure_cli_console", lambda: None)

    # Test with --scan and --yes
    test_args_long = ["main.py", "--scan", "--yes"]
    monkeypatch.setattr("sys.argv", test_args_long)
    with pytest.raises(SystemExit) as exc_info:
        main.main()
    assert exc_info.value.code == 0
    mock_run_scan.assert_called_with(
        config_path="config.json",
        export_csv=None,
        export_json=None,
        consent_granted=True,
    )

    # Test with --scan and -y
    mock_run_scan.reset_mock()
    test_args_short = ["main.py", "--scan", "-y"]
    monkeypatch.setattr("sys.argv", test_args_short)
    with pytest.raises(SystemExit) as exc_info:
        main.main()
    assert exc_info.value.code == 0
    mock_run_scan.assert_called_with(
        config_path="config.json",
        export_csv=None,
        export_json=None,
        consent_granted=True,
    )

    # Test without --yes
    mock_run_scan.reset_mock()
    test_args_no_flag = ["main.py", "--scan"]
    monkeypatch.setattr("sys.argv", test_args_no_flag)
    with pytest.raises(SystemExit) as exc_info:
        main.main()
    assert exc_info.value.code == 0
    mock_run_scan.assert_called_with(
        config_path="config.json",
        export_csv=None,
        export_json=None,
        consent_granted=False,
    )


@pytest.mark.parametrize(
    "falsy_val",
    [
        "false",
        "False",
        "FALSE",
        "0",
        "no",
        "n",
        "off",
        "disable",
        "disabled",
        "",
        None,
        {},
    ],
)
def test_cli_scan_falsy_consent_blocked(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    falsy_val: object,
) -> None:
    """run_cli_scan must block scan and return 1 when authorized_network_consent is falsy (str/None/dict)."""
    cfg_payload = {"security": {"authorized_network_consent": falsy_val}} if falsy_val != {} else {"security": {}}
    config_file = tmp_path / f"config_falsy_{hash(str(falsy_val))}.json"
    config_file.write_text(json.dumps(cfg_payload), encoding="utf-8")

    mock_scan = MagicMock()
    monkeypatch.setattr(ARPScanner, "scan_and_sync", mock_scan)

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=False,
    )
    assert exit_code == 1
    mock_scan.assert_not_called()
    captured = capsys.readouterr()
    assert "NOTICE: Authorized Networks Only" in captured.out


@pytest.mark.parametrize(
    "truthy_val",
    [
        "true",
        "True",
        "TRUE",
        "1",
        "yes",
        "y",
        "on",
        "enable",
        "enabled",
    ],
)
def test_cli_scan_string_truthy_consent_allowed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    dummy_interface: NetworkInterfaceInfo,
    truthy_val: str,
) -> None:
    """run_cli_scan must accept string truthy values like 'true', '1', 'yes' as explicit consent."""
    config_file = tmp_path / f"config_truthy_{hash(truthy_val)}.json"
    config_file.write_text(
        json.dumps({
            "database": {"path": str(tmp_path / "cli_test_truthy.db")},
            "security": {"authorized_network_consent": truthy_val},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(InterfaceDetector, "get_active_interface", lambda pref=None: dummy_interface)
    mock_scan = MagicMock(
        return_value=DiscoveryResult(
            session_id=1,
            interface=dummy_interface,
            discovered_devices=[],
            ip_to_macs={},
            duration_seconds=0.05,
        )
    )
    monkeypatch.setattr(ARPScanner, "scan_and_sync", mock_scan)

    exit_code = run_cli_scan(
        config_path=str(config_file),
        consent_granted=False,
    )
    assert exit_code == 0
    mock_scan.assert_called_once()
    captured = capsys.readouterr()
    assert "NOTICE: Authorized Networks Only" not in captured.out


@pytest.mark.parametrize(
    "input_val,expected",
    [
        (True, True),
        (False, False),
        (None, False),
        (0, False),
        (1, True),
        (-1, True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0", False),
        ("no", False),
        ("n", False),
        ("off", False),
        ("disable", False),
        ("disabled", False),
        ("", False),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("y", True),
        ("on", True),
        ("enable", True),
        ("enabled", True),
        ("unexpected_str", False),
    ],
)
def test_to_bool_and_coerce_bool_matrix(input_val: object, expected: bool) -> None:
    assert to_bool(input_val) == expected
    assert coerce_bool(input_val) == expected


def test_config_manager_boolean_helpers_and_normalization(tmp_path: Path) -> None:
    cfg_file = tmp_path / "test_config_norm.json"
    cfg_file.write_text(
        json.dumps({
            "security": {
                "authorized_network_consent": "false",
                "enable_passive_capture": "1",
                "lock_gateway_mac": "yes",
            }
        }),
        encoding="utf-8",
    )
    cfg = ConfigManager(cfg_file)
    assert cfg.get("security", "authorized_network_consent") is False
    assert cfg.get_bool("security", "authorized_network_consent") is False
    assert cfg.has_authorized_consent() is False
    assert is_consent_granted(cfg) is False

    assert cfg.get("security", "enable_passive_capture") is True
    assert cfg.get_bool("security", "enable_passive_capture") is True
    assert cfg.is_passive_capture_enabled() is True

    assert cfg.get("security", "lock_gateway_mac") is True

    # Test ConfigManager.set normalization
    cfg.set("security", "authorized_network_consent", "true")
    assert cfg.get("security", "authorized_network_consent") is True
    assert cfg.has_authorized_consent() is True

    cfg.set("security", "authorized_network_consent", "0")
    assert cfg.get("security", "authorized_network_consent") is False
    assert cfg.has_authorized_consent() is False


