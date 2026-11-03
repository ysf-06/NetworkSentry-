"""Configuration management for Network Sentry."""

import json
from pathlib import Path
from typing import Any, Dict

from src.utils.logger import get_app_data_dir, resolve_data_path

DEFAULT_CONFIG: Dict[str, Any] = {
    "database": {
        "path": "networksentry.db",
        "wal_mode": True,
        "retention_days": 30,
    },
    "network": {
        "preferred_interface": None,
        "target_cidr": None,
        "scan_interval_seconds": 30,
        "arp_timeout_ms": 1500,
        "rate_limit_pps": 100,
        "max_workers": 24,
        "common_ports": [21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443],
    },
    "security": {
        "lock_gateway_mac": True,
        "alert_on_new_device": True,
        "auto_port_scan_new_devices": False,
        "authorized_network_consent": False,
        "authorized_network_consent_timestamp": None,
        "enable_passive_capture": False,
    },
    "logging": {
        "level": "INFO",
        "file": "networksentry.log",
    },
}



def to_bool(val: Any, default: bool = False) -> bool:
    """Safely coerce various representations (bool, int, str) to a strict boolean.

    Recognizes standard truthy strings ('true', '1', 'yes', 'y', 't', 'on', 'enable', 'enabled')
    and falsy strings ('false', '0', 'no', 'n', 'f', 'off', 'disable', 'disabled', '').
    Defaults to `default` (typically False) for unrecognized strings or non-boolean types.
    """
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, str):
        normalized = val.strip().lower()
        if normalized in ("true", "1", "yes", "y", "t", "on", "enable", "enabled"):
            return True
        if normalized in ("false", "0", "no", "n", "f", "off", "disable", "disabled", ""):
            return False
        return default
    return default


coerce_bool = to_bool


def is_consent_granted(cfg: "ConfigManager") -> bool:
    """Check whether authorized network consent has been explicitly granted in configuration."""
    return cfg.has_authorized_consent()


class ConfigManager:
    """Loads, validates, and persists user configuration in a writable application directory."""

    def __init__(self, config_path: str | Path = "config.json") -> None:
        raw_path = Path(config_path)
        if raw_path.is_absolute() or raw_path.exists():
            self.config_path = raw_path
        else:
            self.config_path = resolve_data_path(raw_path, seed_from_bundle=True)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        if self.config_path.exists():
            try:
                user_cfg = json.loads(self.config_path.read_text(encoding="utf-8"))
                for section, values in user_cfg.items():
                    if isinstance(values, dict) and section in merged:
                        for k, v in values.items():
                            if k in merged[section] and isinstance(DEFAULT_CONFIG[section].get(k), bool):
                                merged[section][k] = to_bool(v, default=DEFAULT_CONFIG[section][k])
                            else:
                                merged[section][k] = v
                    else:
                        merged[section] = values
            except (json.JSONDecodeError, OSError):
                pass
        return merged

    def save(self) -> None:
        """Persist current configuration to disk (falling back to %LOCALAPPDATA%\\NetworkSentry if needed)."""
        target = self.config_path
        if not target.is_absolute():
            target = resolve_data_path(target)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.config_path = target
        except OSError:
            fallback = get_app_data_dir() / target.name
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(
                json.dumps(self.data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self.config_path = fallback

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Retrieve a specific setting by section and key, resolving relative DB/log paths to AppData."""
        val = self.data.get(section, {}).get(key, default)
        if section == "database" and key == "path" and isinstance(val, (str, Path)):
            p = Path(val)
            if not p.is_absolute():
                return str(resolve_data_path(p, seed_from_bundle=False))
        if section == "logging" and key == "file" and isinstance(val, (str, Path)):
            p = Path(val)
            if not p.is_absolute():
                return str(resolve_data_path(p, seed_from_bundle=False))
        return val

    def get_bool(self, section: str, key: str, default: bool = False) -> bool:
        """Retrieve a specific setting coerced to a strict boolean value."""
        val = self.get(section, key, default)
        return to_bool(val, default=default)

    def has_authorized_consent(self) -> bool:
        """Return whether user has granted authorization consent for network scanning."""
        return self.get_bool("security", "authorized_network_consent", False)

    def is_passive_capture_enabled(self) -> bool:
        """Return whether passive packet capture is enabled in configuration."""
        return self.get_bool("security", "enable_passive_capture", False)

    def set(self, section: str, key: str, value: Any) -> None:
        """Set a configuration value under section and key, normalizing boolean schema keys."""
        if section not in self.data or not isinstance(self.data[section], dict):
            self.data[section] = {}
        if (
            section in DEFAULT_CONFIG
            and key in DEFAULT_CONFIG[section]
            and isinstance(DEFAULT_CONFIG[section][key], bool)
        ):
            self.data[section][key] = to_bool(value, default=DEFAULT_CONFIG[section][key])
        else:
            self.data[section][key] = value


