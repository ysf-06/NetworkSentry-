"""Configuration management for Network Sentry."""

import json
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "database": {
        "path": "networksentry.db",
        "wal_mode": True,
    },
    "network": {
        "preferred_interface": None,
        "scan_interval_seconds": 30,
        "arp_timeout_ms": 1500,
        "common_ports": [21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443],
    },
    "security": {
        "lock_gateway_mac": True,
        "alert_on_new_device": True,
        "auto_port_scan_new_devices": True,
    },
    "logging": {
        "level": "INFO",
        "file": "networksentry.log",
    },
}


class ConfigManager:
    """Loads, validates, and persists user configuration."""

    def __init__(self, config_path: str | Path = "config.json") -> None:
        self.config_path = Path(config_path)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        if self.config_path.exists():
            try:
                user_cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                for section, values in user_cfg.items():
                    if isinstance(values, dict) and section in merged:
                        merged[section].update(values)
                    else:
                        merged[section] = values
            except (json.JSONDecodeError, OSError):
                pass
        return merged

    def save(self) -> None:
        """Persist current configuration to disk."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Retrieve a specific setting by section and key."""
        return self.data.get(section, {}).get(key, default)

