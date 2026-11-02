"""Desktop and system tray notification dispatcher for Network Sentry."""

import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional

from src.database.models import SecurityAlertRecord
from src.utils.logger import setup_logger

logger = setup_logger("Notifier")


@dataclass
class NotificationEvent:
    """Record of a dispatched user notification."""

    title: str
    message: str
    severity: str = "INFO"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


class SystemNotifier:
    """Dispatches desktop notifications via Qt System Tray or OS native tools."""

    def __init__(self, enabled: bool = True, tray_icon: Optional[Any] = None) -> None:
        self.enabled = enabled
        self.tray_icon = tray_icon
        self.history: List[NotificationEvent] = []

    def set_tray_icon(self, tray_icon: Any) -> None:
        """Attach a QSystemTrayIcon instance for native GUI balloon/toast notifications."""
        self.tray_icon = tray_icon

    def notify(self, title: str, message: str, severity: str = "INFO") -> NotificationEvent:
        """Send a desktop notification and record it in history."""
        event = NotificationEvent(title=title, message=message, severity=severity.upper())
        self.history.append(event)
        logger.info("Notification [%s] %s: %s", event.severity, title, message)

        if not self.enabled:
            return event

        # 1. Prefer Qt QSystemTrayIcon if attached and visible
        if self.tray_icon is not None:
            try:
                if hasattr(self.tray_icon, "supportsMessages") and self.tray_icon.supportsMessages():
                    from PySide6.QtWidgets import QSystemTrayIcon

                    icon_map = {
                        "INFO": QSystemTrayIcon.MessageIcon.Information,
                        "WARNING": QSystemTrayIcon.MessageIcon.Warning,
                        "CRITICAL": QSystemTrayIcon.MessageIcon.Critical,
                    }
                    q_icon = icon_map.get(event.severity, QSystemTrayIcon.MessageIcon.Information)
                    self.tray_icon.showMessage(title, message, q_icon, 5000)
                    return event
            except Exception as exc:
                logger.debug("Tray notification fallback: %s", exc)

        # 2. Linux notify-send fallback when no tray icon is active
        if platform.system().lower() == "linux" and shutil.which("notify-send"):
            try:
                urgency = "critical" if event.severity == "CRITICAL" else "normal"
                subprocess.Popen(
                    ["notify-send", "-u", urgency, title, message],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                pass

        return event

    def notify_alert(self, alert: SecurityAlertRecord) -> NotificationEvent:
        """Format and dispatch a notification for a `SecurityAlertRecord`."""
        title_map = {
            "ARP_SPOOFING": "CRITICAL: ARP Spoofing / MITM Detected!",
            "NEW_DEVICE": "New Device Joined Network",
            "SUSPICIOUS_PORT": "High-Risk Open Port Detected",
            "MAC_FLAPPING": "Network MAC Anomaly Detected",
        }
        title = title_map.get(alert.alert_type, f"Security Alert: {alert.alert_type}")
        return self.notify(title=title, message=alert.description, severity=alert.severity)
