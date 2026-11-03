"""Unit and integration tests for Localhost Port Scanner Verification Mode."""

import errno
import socket

import pytest

from src.security.port_scanner import PortScanner


def test_localhost_port_verification_success() -> None:
    """Verify that PortScanner.run_localhost_verification() succeeds with open probe and closed rejection."""
    result = PortScanner.run_localhost_verification(banner_text="SSH-2.0-NetworkSentryLocalhostTest")
    if result.get("sandbox_restricted"):
        pytest.skip("Localhost sockets restricted by environment policy (WSAEACCES 10013)")
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
    if result.get("sandbox_restricted"):
        pytest.skip("Localhost sockets restricted by environment policy (WSAEACCES 10013)")
    assert result["success"] is True
    assert result["banner_matched"] is True
    assert banner in result["record"].banner
    assert banner in result["banner"]


def test_localhost_port_verification_empty_banner() -> None:
    """Verify localhost test works even when no banner is sent."""
    result = PortScanner.run_localhost_verification(banner_text="")
    if result.get("sandbox_restricted"):
        pytest.skip("Localhost sockets restricted by environment policy (WSAEACCES 10013)")
    assert result["success"] is True
    assert result["detected"] is True
    assert result["error"] is None


def test_localhost_port_verification_wsaeacces_bind_handling(monkeypatch) -> None:
    """Verify that WSAEACCES (10013) on bind returns sandbox_restricted=True with a clean diagnostic message."""
    orig_socket = socket.socket

    class RestrictedBindSocket:
        def __init__(self, *args, **kwargs):
            self._real = orig_socket(*args, **kwargs)

        def setsockopt(self, *args, **kwargs):
            pass

        def bind(self, addr):
            err = OSError(errno.EACCES, "An attempt was made to access a socket in a way forbidden by its access permissions")
            err.winerror = 10013
            raise err

        def close(self):
            try:
                self._real.close()
            except OSError:
                pass

    monkeypatch.setattr(socket, "socket", RestrictedBindSocket)
    res = PortScanner.run_localhost_verification()
    assert res["success"] is False
    assert res["sandbox_restricted"] is True
    assert res["state"] == "RESTRICTED"
    assert "WSAEACCES" in res["message"] or "10013" in res["message"]
    assert res["error"] is not None


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

    captured_box = {}

    def mock_info(parent, title, text):
        captured_box["title"] = title
        captured_box["text"] = text

    def mock_warning(parent, title, text):
        captured_box["title"] = title
        captured_box["text"] = text

    monkeypatch.setattr(QMessageBox, "information", mock_info)
    monkeypatch.setattr(QMessageBox, "warning", mock_warning)

    win.run_localhost_port_test()

    title = captured_box.get("title", "")
    if "Sandbox Restricted" in title or "Notice" in title:
        pytest.skip("Localhost sockets restricted by environment policy (WSAEACCES 10013)")

    assert "Localhost Verification Passed" in title
    text = captured_box.get("text", "")
    assert "None:None" not in text
    assert "State: None" not in text
    assert "127.0.0.1:" in text
    assert "State: OPEN" in text
    win.close()


def test_localhost_port_verification_wsaeacces_connect_handling(monkeypatch) -> None:
    """Verify that WSAEACCES (10013) on probe/connect returns sandbox_restricted=True even when bind() succeeds."""
    orig_socket = socket.socket

    class RestrictedConnectSocket:
        def __init__(self, *args, **kwargs):
            self._real = orig_socket(*args, **kwargs)

        def setsockopt(self, *args, **kwargs):
            return self._real.setsockopt(*args, **kwargs)

        def bind(self, addr):
            return self._real.bind(addr)

        def listen(self, backlog):
            return self._real.listen(backlog)

        def getsockname(self):
            return self._real.getsockname()

        def settimeout(self, t):
            return self._real.settimeout(t)

        def accept(self):
            err = OSError(errno.EACCES, "Localhost access blocked by policy (WSAEACCES 10013)")
            err.winerror = 10013
            raise err

        def connect_ex(self, addr):
            return 10013

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def close(self):
            try:
                self._real.close()
            except OSError:
                pass

    monkeypatch.setattr(socket, "socket", RestrictedConnectSocket)
    res = PortScanner.run_localhost_verification()
    assert res["success"] is False
    assert res["sandbox_restricted"] is True
    assert res["state"] == "RESTRICTED"
    assert "WSAEACCES" in res["message"] or "10013" in res["message"]


def test_gui_run_localhost_port_test_sandbox_restricted_notice(tmp_path, monkeypatch) -> None:
    """Verify that MainWindow.run_localhost_port_test displays the dedicated warning dialog when sandbox_restricted=True."""
    import os

    from PySide6.QtWidgets import QApplication, QMessageBox

    from src.gui.main_window import MainWindow
    from src.utils.config import ConfigManager

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    _ = QApplication.instance() or QApplication([])

    cfg_file = tmp_path / "test_gui_restricted_cfg.json"
    cfg = ConfigManager(cfg_file)
    cfg.set("database", "path", str(tmp_path / "test_gui_restricted.db"))
    cfg.set("security", "authorized_network_consent", True)
    cfg.save()

    win = MainWindow(config=cfg)

    captured_box = {}

    def mock_warning(parent, title, text):
        captured_box["title"] = title
        captured_box["text"] = text

    monkeypatch.setattr(QMessageBox, "warning", mock_warning)
    monkeypatch.setattr(
        win.port_scanner,
        "run_localhost_verification",
        lambda **kwargs: {
            "success": False,
            "sandbox_restricted": True,
            "message": "Localhost socket connection blocked by Windows sandbox/security policy (WSAEACCES 10013).",
        },
    )

    win.run_localhost_port_test()

    assert "Sandbox Restricted" in captured_box.get("title", "") or "Notice" in captured_box.get("title", "")
    assert "WSAEACCES 10013" in captured_box.get("text", "")
    assert "RESTRICTED" in win.status_bar.currentMessage()
    win.close()


def test_gui_run_localhost_port_test_failure_dialog(tmp_path, monkeypatch) -> None:
    """Verify that MainWindow.run_localhost_port_test displays failure warning on standard port probe error."""
    import os

    from PySide6.QtWidgets import QApplication, QMessageBox

    from src.gui.main_window import MainWindow
    from src.utils.config import ConfigManager

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    _ = QApplication.instance() or QApplication([])

    cfg_file = tmp_path / "test_gui_fail_cfg.json"
    cfg = ConfigManager(cfg_file)
    cfg.set("database", "path", str(tmp_path / "test_gui_fail.db"))
    cfg.set("security", "authorized_network_consent", True)
    cfg.save()

    win = MainWindow(config=cfg)

    captured_box = {}

    def mock_warning(parent, title, text):
        captured_box["title"] = title
        captured_box["text"] = text

    monkeypatch.setattr(QMessageBox, "warning", mock_warning)
    monkeypatch.setattr(
        win.port_scanner,
        "run_localhost_verification",
        lambda **kwargs: {
            "success": False,
            "sandbox_restricted": False,
            "message": "Probe timed out.",
            "error": "Probe timed out.",
        },
    )

    win.run_localhost_port_test()

    assert "Localhost Verification Failed" in captured_box.get("title", "")
    assert "Probe timed out" in captured_box.get("text", "")
    assert "FAILED" in win.status_bar.currentMessage()
    win.close()



