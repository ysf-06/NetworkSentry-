"""Release Packaging and Artifact Checksum Generator for Network Sentry."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

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


def find_signtool(explicit_path: str | Path | None = None) -> Optional[Path]:
    """Locate signtool.exe via argument, SIGNTOOL_PATH, PATH, or Windows SDKs."""
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return p

    env_path = os.environ.get("SIGNTOOL_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    which_path = shutil.which("signtool.exe") or shutil.which("signtool")
    if which_path:
        return Path(which_path)

    if platform.system().lower() == "windows":
        sdk_roots = [
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Kits" / "10" / "bin",
        ]
        for root in sdk_roots:
            if root.exists():
                matches = sorted(root.glob("*/x64/signtool.exe"), reverse=True)
                if matches:
                    return matches[0]

        app_cert_roots = [
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Windows Kits"
            / "10"
            / "App Certification Kit"
            / "signtool.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Windows Kits"
            / "10"
            / "App Certification Kit"
            / "signtool.exe",
        ]
        for app_cert in app_cert_roots:
            if app_cert.exists():
                return app_cert

    return None


def sign_binary(
    target: Path,
    signtool: Path,
    cert_path: Path,
    cert_password: Optional[str] = None,
    timestamp_url: Optional[str] = "http://timestamp.digicert.com",
    description: Optional[str] = "Cyber Guardian (Network Sentry)",
) -> bool:
    """Sign a PE binary using Microsoft signtool.exe with SHA-256 Authenticode."""
    if not target.exists():
        return False

    cmd = [
        str(signtool),
        "sign",
        "/fd",
        "SHA256",
        "/f",
        str(cert_path),
    ]
    if cert_password:
        cmd.extend(["/p", cert_password])
    if timestamp_url:
        cmd.extend(["/tr", timestamp_url, "/td", "SHA256"])
    if description:
        cmd.extend(["/d", description])
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            print(f"[+] Successfully signed: {target.name}")
            return True
        err = proc.stderr.strip() or proc.stdout.strip()
        print(f"[!] Warning: Code signing failed for {target.name} (code {proc.returncode}): {err}")
        return False
    except Exception as e:
        print(f"[!] Warning: Failed to invoke signtool for {target.name}: {e}")
        return False


def sign_release_artifacts(
    dist_dir: Path,
    cert_path: Optional[str | Path] = None,
    cert_password: Optional[str] = None,
    timestamp_url: Optional[str] = "http://timestamp.digicert.com",
    signtool_path: Optional[str | Path] = None,
    skip_sign: bool = False,
) -> bool:
    """Validate prerequisites and sign distribution binaries before archiving."""
    if skip_sign:
        print("[i] Windows Authenticode signing: Skipped via --skip-sign flag.")
        return True

    if platform.system().lower() != "windows":
        print(f"[i] Windows Authenticode signing: Skipped on non-Windows platform ({platform.system()}).")
        return True

    if not cert_path:
        print(
            "[i] Windows Authenticode signing: No code-signing certificate provided via --cert "
            "or CODE_SIGN_CERT_PATH. Continuing build without signing."
        )
        return True

    cert = Path(cert_path)
    if not cert.exists():
        print(f"[!] Warning: Code-signing certificate file not found at '{cert}'. Continuing build without signing.")
        return True

    signtool = find_signtool(signtool_path)
    if not signtool:
        print("[!] Warning: Microsoft signtool.exe not found on PATH or in Windows SDK. Continuing build without signing.")
        return True

    candidates = [
        dist_dir / "NetworkSentry" / "NetworkSentry.exe",
        PROJECT_ROOT / "src" / "native" / "packet_parser.dll",
        dist_dir / "NetworkSentry" / "_internal" / "src" / "native" / "packet_parser.dll",
        dist_dir / "NetworkSentry" / "src" / "native" / "packet_parser.dll",
    ]
    seen: set[Path] = set()
    to_sign: list[Path] = []
    for c in candidates:
        if c.exists():
            resolved = c.resolve()
            if resolved not in seen:
                seen.add(resolved)
                to_sign.append(c)

    if not to_sign:
        print("[*] No binary targets found to sign.")
        return True

    print(f"[*] Signing {len(to_sign)} binary artifacts with signtool ({signtool.name})...")
    success = True
    for target in to_sign:
        ok = sign_binary(
            target=target,
            signtool=signtool,
            cert_path=cert,
            cert_password=cert_password,
            timestamp_url=timestamp_url,
        )
        if not ok:
            success = False

    return success


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse packaging command line options and environment variable fallbacks."""
    parser = argparse.ArgumentParser(description="Package Network Sentry and sign release artifacts.")
    parser.add_argument(
        "--cert",
        "--cert-path",
        dest="cert_path",
        default=os.environ.get("CODE_SIGN_CERT_PATH"),
        help="Path to code signing PFX/P12 certificate file (or CODE_SIGN_CERT_PATH env var).",
    )
    parser.add_argument(
        "--password",
        "--cert-password",
        dest="cert_password",
        default=os.environ.get("CODE_SIGN_CERT_PASSWORD"),
        help="Password for code signing certificate (or CODE_SIGN_CERT_PASSWORD env var).",
    )
    parser.add_argument(
        "--timestamp-url",
        dest="timestamp_url",
        default=os.environ.get("CODE_SIGN_TIMESTAMP_URL", "http://timestamp.digicert.com"),
        help="RFC 3161 timestamp server URL (default: http://timestamp.digicert.com).",
    )
    parser.add_argument(
        "--signtool",
        dest="signtool_path",
        default=os.environ.get("SIGNTOOL_PATH"),
        help="Explicit path to signtool.exe (or SIGNTOOL_PATH env var).",
    )
    parser.add_argument(
        "--skip-sign",
        dest="skip_sign",
        action="store_true",
        default=False,
        help="Explicitly skip Authenticode code signing.",
    )
    return parser.parse_args(argv)


def package_and_compute_checksums(
    argv: Sequence[str] | None = None,
    dist_dir: Optional[Path] = None,
    cert_path: Optional[str | Path] = None,
    cert_password: Optional[str] = None,
    timestamp_url: Optional[str] = None,
    signtool_path: Optional[str | Path] = None,
    skip_sign: Optional[bool] = None,
) -> int:
    """Generate release notes, clean build artifacts, sign binaries, archive, and compute checksums."""
    print(f"[*] Packaging Cyber Guardian v{__version__}...")
    if dist_dir is None:
        dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    args = parse_args(argv if argv is not None else [])
    effective_cert = cert_path if cert_path is not None else args.cert_path
    effective_password = cert_password if cert_password is not None else args.cert_password
    effective_ts = timestamp_url if timestamp_url is not None else args.timestamp_url
    effective_signtool = signtool_path if signtool_path is not None else args.signtool_path
    effective_skip_sign = skip_sign if skip_sign is not None else args.skip_sign

    # 1. Generate release notes
    notes_file = generate_release_notes(dist_dir)
    print(f"[+] Release notes written to: {notes_file}")

    # 2. Clean leftover runtime files from previous test/dev runs in dist
    app_folder = dist_dir / "NetworkSentry"
    if app_folder.exists() and app_folder.is_dir():
        for stale in app_folder.glob("networksentry.db*"):
            try:
                stale.unlink()
                print(f"[*] Cleaned leftover release database: {stale.name}")
            except OSError:
                pass
        for stale_log in app_folder.glob("*.log"):
            try:
                stale_log.unlink()
                print(f"[*] Cleaned leftover release log: {stale_log.name}")
            except OSError:
                pass

    # 3. Authenticode Code Signing (executed BEFORE archiving and hashing)
    sign_release_artifacts(
        dist_dir=dist_dir,
        cert_path=effective_cert,
        cert_password=effective_password,
        timestamp_url=effective_ts,
        signtool_path=effective_signtool,
        skip_sign=effective_skip_sign,
    )

    # 4. Collect critical binaries and files for checksum verification
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

    # 5. Create zip archive if dist/NetworkSentry directory exists
    if app_folder.exists() and app_folder.is_dir():
        zip_name = dist_dir / f"NetworkSentry-v{__version__}-windows-x64"
        print(f"[*] Creating release archive: {zip_name}.zip...")
        archive_path = Path(shutil.make_archive(str(zip_name), "zip", root_dir=dist_dir, base_dir="NetworkSentry"))
        targets_to_hash.append(archive_path)
        print(f"[+] Archive created: {archive_path}")

    # 6. Write release_checksums.txt
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

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]
    return package_and_compute_checksums(argv=argv)


if __name__ == "__main__":
    sys.exit(main())
