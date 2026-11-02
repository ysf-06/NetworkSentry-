"""Offline MAC OUI (Organizationally Unique Identifier) vendor lookup."""

import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional


def _resolve_default_oui_path() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass = Path(getattr(sys, "_MEIPASS"))
        candidate = meipass / "assets" / "oui_database.json"
        if candidate.exists():
            return candidate
    return Path(__file__).resolve().parents[2] / "assets" / "oui_database.json"


DEFAULT_OUI_PATH = _resolve_default_oui_path()

# Known virtual/container prefixes that use the Locally Administered bit
KNOWN_VIRTUAL_LAA_PREFIXES: Dict[str, str] = {
    "02:42:AC": "Docker Container Network",
    "02:50:F2": "Microsoft Corp. (Virtual/NDIS Adapter)",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "54:52:00": "Linux KVM Virtual Machine",
    "0A:00:27": "Oracle VirtualBox Host-Only Adapter",
}


class OUILookup:
    """Resolves MAC addresses to hardware manufacturer names using a local offline database."""

    def __init__(self, database_path: Optional[str | Path] = None) -> None:
        self.database_path = Path(database_path) if database_path else DEFAULT_OUI_PATH
        self._oui_map: Dict[str, str] = {}
        self._load_database()

    def _load_database(self) -> None:
        """Load OUI mappings from the JSON database file."""
        self._oui_map.update(KNOWN_VIRTUAL_LAA_PREFIXES)
        if not self.database_path.exists():
            return
        try:
            raw_data = json.loads(self.database_path.read_text(encoding="utf-8"))
            if isinstance(raw_data, dict):
                for prefix, vendor in raw_data.items():
                    clean_prefix = self._normalize_prefix(str(prefix))
                    if clean_prefix:
                        self._oui_map[clean_prefix] = str(vendor).strip()
        except (OSError, json.JSONDecodeError):
            pass

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        """Normalize a 3-byte OUI prefix to 'XX:XX:XX' format."""
        hex_only = re.sub(r"[^0-9A-Fa-f]", "", prefix).upper()
        if len(hex_only) < 6:
            return ""
        hex6 = hex_only[:6]
        return f"{hex6[0:2]}:{hex6[2:4]}:{hex6[4:6]}"

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """
        Normalize any common MAC address representation to 'AA:BB:CC:DD:EE:FF'.
        Returns an empty string if the input is not a valid 48-bit MAC address.
        """
        if not mac or not isinstance(mac, str):
            return ""
        stripped = mac.strip()

        # Check colon or hyphen separated octets (allowing 1 or 2 hex digits per octet, e.g. arp -a)
        if ":" in stripped or "-" in stripped:
            sep = ":" if ":" in stripped else "-"
            parts = stripped.split(sep)
            if len(parts) == 6 and all(1 <= len(p) <= 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
                return ":".join(p.upper().zfill(2) for p in parts)

        # Fallback: strip dots/separators and require exact 12 hex characters
        hex_only = re.sub(r"[^0-9A-Fa-f]", "", stripped).upper()
        if len(hex_only) != 12:
            return ""
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))

    @classmethod
    def is_valid_mac(cls, mac: str) -> bool:
        """Return True if the string represents a valid 6-byte MAC address."""
        norm = cls.normalize_mac(mac)
        return len(norm) == 17 and norm != "00:00:00:00:00:00"

    @classmethod
    def is_randomized_mac(cls, mac: str) -> bool:
        """
        Return True if the MAC address has the Locally Administered Address (LAA) bit set
        (bit 1 of the first octet is 1, and multicast bit 0 is 0) and is not a known VM prefix.
        Modern iOS, Android, and Windows devices use LAA for Wi-Fi MAC randomization.
        """
        norm = cls.normalize_mac(mac)
        if not norm:
            return False
        prefix = norm[:8]
        if prefix in KNOWN_VIRTUAL_LAA_PREFIXES:
            return False
        first_byte = int(norm[:2], 16)
        is_locally_administered = (first_byte & 0x02) != 0
        is_unicast = (first_byte & 0x01) == 0
        return is_locally_administered and is_unicast

    def lookup(self, mac: str) -> str:
        """Resolve a MAC address to its manufacturer or address category."""
        norm = self.normalize_mac(mac)
        if not norm or norm == "00:00:00:00:00:00":
            return "Unknown Vendor"

        if norm == "FF:FF:FF:FF:FF:FF":
            return "Broadcast"
        if norm.startswith("01:00:5E"):
            return "IPv4 Multicast"
        if norm.startswith("33:33:"):
            return "IPv6 Multicast"

        prefix = norm[:8]
        if prefix in self._oui_map:
            return self._oui_map[prefix]

        if self.is_randomized_mac(norm):
            return "Randomized / Private MAC"

        return "Unknown Vendor"

    @property
    def count(self) -> int:
        """Return the number of loaded OUI prefixes."""
        return len(self._oui_map)
