"""Unit and integration tests for Localhost Port Scanner Verification Mode."""

from src.security.port_scanner import PortScanner


def test_localhost_port_verification_success() -> None:
    """Verify that PortScanner.run_localhost_verification() succeeds with open probe and closed rejection."""
    result = PortScanner.run_localhost_verification(banner_text="SSH-2.0-NetworkSentryLocalhostTest")
    assert result["success"] is True
    assert result["detected"] is True
    assert result["negative_check_passed"] is True
    assert result["banner_matched"] is True
    assert result["open_port"] > 0
    assert result["closed_port"] > 0
    assert result["open_port"] != result["closed_port"]
    assert result["record"] is not None
    assert result["record"].state == "OPEN"
    assert "SSH-2.0-NetworkSentryLocalhostTest" in result["record"].banner
    assert result["host"] == "127.0.0.1"
    assert result["port"] == result["open_port"]
    assert result["state"] == "OPEN"
    assert "service" in result
    assert result["error"] is None
    assert result["elapsed_ms"] >= 0.0


def test_localhost_port_verification_custom_banner() -> None:
    """Verify localhost test works with a custom banner string."""
    banner = "HTTP/1.1 200 OK Server: NetworkSentryDaemon"
    result = PortScanner.run_localhost_verification(banner_text=banner)
    assert result["success"] is True
    assert result["banner_matched"] is True
    assert banner in result["record"].banner
    assert banner in result["banner"]


def test_localhost_port_verification_empty_banner() -> None:
    """Verify localhost test works even when no banner is sent."""
    result = PortScanner.run_localhost_verification(banner_text="")
    assert result["success"] is True
    assert result["detected"] is True
    assert result["error"] is None


def test_gui_run_localhost_port_test_execution(tmp_path, monkeypatch) -> None:
    """Verify that MainWindow.run_localhost_port_test handles execution and unpacks result cleanly without None:None."""
    import os

    from PySide6.QtWidgets import QApplication, QMessageBox

    from src.gui.main_window import MainWindow
    from src.utils.config import ConfigManager

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    _ = QApplication.instance() or QApplication([])

    cfg_file = tmp_path / "test_gui_cfg.json"
    cfg = ConfigManager(cfg_file)
    cfg.set("database", "path", str(tmp_path / "test_gui.db"))
    cfg.set("security", "authorized_network_consent", True)
    cfg.save()

    win = MainWindow(config=cfg)

    # Monkeypatch QMessageBox.information to capture the formatted dialog string
    captured_box = {}

    def mock_info(parent, title, text):
        captured_box["title"] = title
        captured_box["text"] = text

    monkeypatch.setattr(QMessageBox, "information", mock_info)

    win.run_localhost_port_test()

    assert "Localhost Verification Passed" in captured_box.get("title", "")
    text = captured_box.get("text", "")
    assert "None:None" not in text
    assert "State: None" not in text
    assert "127.0.0.1:" in text
    assert "State: OPEN" in text
    win.close()

