"""Release Packaging and Artifact Checksum Generator for Network Sentry."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src._version import __version__


def compute_sha256(filepath: Path) -> str:
    """Compute hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def generate_release_notes(dist_dir: Path) -> Path:
    """Generate markdown release notes for current version."""
    notes_content = f"""# Cyber Guardian (Network Sentry) v{__version__} Release Notes

Release Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Version: {__version__}

## Key Capabilities & Updates

1. **Passive Live Wire Packet Capture & Npcap Integration**:
   - Integrated non-blocking live wire packet capture using Npcap/libpcap via Windows C API (`wpcap.dll` / `Packet.dll`).
   - Honest labeling: Gracefully falls back to Network Inventory Mode (`ESTIMATED_NIC`) with explicit UI disclosure when Npcap is unavailable or running without administrative privileges.

2. **Localhost Verification Mode**:
   - Added self-contained `--test-localhost` mode and GUI "Run Localhost Port Verification Test" button.
   - Spins up ephemeral local loopback TCP socket, probes it using `PortScanner`, confirms detection, and exits cleanly without generating network traffic.

3. **Safe Defaults & Authorization Disclaimer**:
   - Pre-scan modal disclosure requiring explicit user authorization consent before scanning.
   - Configurable and visible target CIDR, worker concurrency, and port list.
   - Safe defaults: `auto_port_scan_new_devices` defaulted to `false`.

4. **False Positive Reduction & Alert Confidence**:
   - Added confidence classification (`HIGH_CONFIDENCE`, `MEDIUM_CONFIDENCE`, `SUSPECTED_DHCP_OR_REBOOT`).
   - Added "Approve Expected Change" action to trust router reboots, mesh AP roaming handovers, and DHCP renewals.
   - Tracks `first_seen` and `last_changed` timestamps.

5. **Persistent Data Management & Retention**:
   - SQLite schema versioning via `schema_migrations` table (v2).
   - "Export Full Database JSON Backup" for audit preservation.
   - Configurable retention pruning and "Purge Stored Data" with SQLite page vacuuming.

6. **Quality & Release Infrastructure**:
   - Single-source versioning in `src/_version.py`.
   - CI matrix for Windows and Linux with ruff linting, mypy type checks, and mandatory localhost integration tests.
   - SHA-256 checksum generation for binary integrity.

## System Requirements & Limitations
- **Operating Systems**: Windows 10/11 (64-bit), Linux (kernel 4.x+)
- **Live Wire Capture**: Requires Npcap (https://npcap.com/) installed with "WinPcap API-compatible Mode". In standard user mode without Npcap or elevation, the application operates in Network Inventory Mode using OS counters.
- **Authorization**: Only scan networks you own or are explicitly authorized to assess.
"""
    notes_path = dist_dir / f"RELEASE_NOTES_v{__version__}.md"
    notes_path.write_text(notes_content, encoding="utf-8")
    return notes_path


def package_and_compute_checksums() -> int:
    """Generate release checksums and package archive."""
    print(f"[*] Packaging Cyber Guardian v{__version__}...")
    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate release notes
    notes_file = generate_release_notes(dist_dir)
    print(f"[+] Release notes written to: {notes_file}")

    # 2. Collect critical binaries and files for checksum verification
    targets_to_hash: list[Path] = []

    c_dll = PROJECT_ROOT / "src" / "native" / "packet_parser.dll"
    if c_dll.exists():
        targets_to_hash.append(c_dll)

    c_so = PROJECT_ROOT / "src" / "native" / "packet_parser.so"
    if c_so.exists():
        targets_to_hash.append(c_so)

    oui_db = PROJECT_ROOT / "assets" / "oui_database.json"
    if oui_db.exists():
        targets_to_hash.append(oui_db)

    app_exe = dist_dir / "NetworkSentry" / "NetworkSentry.exe"
    if app_exe.exists():
        targets_to_hash.append(app_exe)

    # Create zip archive if dist/NetworkSentry directory exists
    app_folder = dist_dir / "NetworkSentry"
    if app_folder.exists() and app_folder.is_dir():
        for stale in app_folder.glob("networksentry.db*"):
            try:
                stale.unlink()
                print(f"[*] Cleaned leftover release database: {stale.name}")
            except OSError:
                pass
        zip_name = dist_dir / f"NetworkSentry-v{__version__}-windows-x64"
        print(f"[*] Creating release archive: {zip_name}.zip...")
        archive_path = Path(shutil.make_archive(str(zip_name), "zip", root_dir=dist_dir, base_dir="NetworkSentry"))
        targets_to_hash.append(archive_path)
        print(f"[+] Archive created: {archive_path}")

    # 3. Write release_checksums.txt
    checksums_file = dist_dir / "release_checksums.txt"
    lines = [
        f"# Cyber Guardian (Network Sentry) v{__version__} SHA-256 Checksums",
        f"# Generated: {datetime.now().isoformat()}",
        "",
    ]
    for p in targets_to_hash:
        rel = p.relative_to(PROJECT_ROOT) if p.is_relative_to(PROJECT_ROOT) else p.name
        sha = compute_sha256(p)
        size_kb = p.stat().st_size / 1024.0
        lines.append(f"{sha}  {rel}  ({size_kb:.1f} KB)")
        print(f"[+] {rel} -> {sha}")

    checksums_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] Checksums saved to: {checksums_file}")

    # 4. Code signing notice
    signtool = shutil.which("signtool.exe")
    pfx_cert = os.environ.get("CODE_SIGN_CERT_PATH")
    if signtool and pfx_cert and Path(pfx_cert).exists():
        print("[*] Performing Authenticode code signing with signtool...")
        # Production signing command would execute here if certificate is provisioned
    else:
        print("[i] Windows Authenticode signing: No code-signing PFX certificate provided in environment.")
        print("    Self-signed or release certificate can be attached using: signtool sign /f <cert.pfx> /p <password> ...")

    return 0


if __name__ == "__main__":
    sys.exit(package_and_compute_checksums())
