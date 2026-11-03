"""Generate version-locked and sha256-hashed requirements-lock.txt for NetworkSentry."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
import urllib.request
from pathlib import Path
from typing import Sequence

# Project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Complete runtime and development closure of requirements.txt on Python 3.12
# (excl. pyinstaller packaging-only tools)
LOCKED_PACKAGES: list[tuple[str, str]] = [
    ("ast_serialize", "0.13.1"),
    ("boolean.py", "5.0"),
    ("CacheControl", "0.14.4"),
    ("certifi", "2026.10.23"),
    ("charset-normalizer", "3.5.2"),
    ("colorama", "0.4.6"),
    ("coverage", "7.17.1"),
    ("cyclonedx-python-lib", "11.12.0"),
    ("defusedxml", "0.7.1"),
    ("filelock", "4.2.7"),
    ("idna", "3.20"),
    ("iniconfig", "2.3.1"),
    ("librt", "0.16.0"),
    ("license-expression", "30.4.4"),
    ("markdown-it-py", "4.2.0"),
    ("mdurl", "0.1.2"),
    ("msgpack", "1.2.4"),
    ("mypy", "2.4.1"),
    ("mypy_extensions", "1.1.0"),
    ("packageurl-python", "0.17.6"),
    ("packaging", "26.3"),
    ("pathspec", "1.1.1"),
    ("pip", "26.3"),
    ("pip_api", "0.0.35"),
    ("pip_audit", "2.10.1"),
    ("pip-requirements-parser", "32.0.1"),
    ("platformdirs", "4.14.3"),
    ("pluggy", "1.7.0"),
    ("psutil", "7.2.2"),
    ("py-serializable", "2.1.0"),
    ("Pygments", "2.21.0"),
    ("pyparsing", "3.3.3"),
    ("PySide6", "6.12.0"),
    ("PySide6_Addons", "6.12.0"),
    ("PySide6_Essentials", "6.12.0"),
    ("PySide6_Pdf", "6.12.0.140"),
    ("PySide6_WebEngine", "6.12.0.140"),
    ("pytest", "9.2.0"),
    ("pytest-cov", "7.1.0"),
    ("requests", "2.34.2"),
    ("rich", "15.0.0"),
    ("ruff", "0.17.3"),
    ("shiboken6", "6.12.0"),
    ("sortedcontainers", "2.4.0"),
    ("tomli", "2.5.0"),
    ("tomli_w", "1.2.0"),
    ("types-psutil", "7.2.2.20260906"),
    ("typing_extensions", "4.16.0"),
    ("urllib3", "2.8.0"),
]


def fetch_package_hashes(pkg_info: tuple[str, str], timeout: float = 15.0) -> tuple[str, str, list[str], str | None]:
    """Fetch SHA-256 release hashes from PyPI JSON API for a given package and version."""
    name, ver = pkg_info
    url = f"https://pypi.org/pypi/{name}/{ver}/json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetworkSentry-Lock-Gen/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            hashes: list[str] = []
            for file_info in data.get("urls", []):
                sha256 = file_info.get("digests", {}).get("sha256")
                if sha256:
                    hashes.append(sha256)
            return name, ver, hashes, None
    except Exception as exc:
        return name, ver, [], str(exc)


def build_lock_content(
    results: Sequence[tuple[str, str, Sequence[str], str | None]],
) -> str:
    """Format package versions and sorted SHA-256 hashes into requirements-lock.txt format."""
    lines: list[str] = [
        "# NetworkSentry Locked Dependencies with SHA-256 Hashes",
        "# Auto-generated for multi-platform CI/CD (Windows, Linux, macOS) and clean environments.",
        "# Enforces strict version pinning (==) and cryptographic integrity via pip --require-hashes.",
        "",
    ]

    # Sort results case-insensitively by package name
    sorted_results = sorted(results, key=lambda r: r[0].lower())

    for name, ver, hashes, err in sorted_results:
        if err:
            raise RuntimeError(f"Failed to fetch PyPI metadata for {name}=={ver}: {err}")
        unique_hashes = sorted(list(set(hashes)))
        if not unique_hashes:
            raise ValueError(f"No SHA-256 digests found on PyPI for {name}=={ver}")

        line_parts = [f"{name}=={ver} \\"]
        for i, h in enumerate(unique_hashes):
            is_last = i == len(unique_hashes) - 1
            suffix = "" if is_last else " \\"
            line_parts.append(f"    --hash=sha256:{h}{suffix}")
        lines.append("\n".join(line_parts))

    return "\n".join(lines) + "\n"


def generate_lock_file(
    output_path: Path,
    packages: list[tuple[str, str]] | None = None,
    workers: int = 10,
    timeout: float = 15.0,
) -> int:
    """Fetch package hashes and write the lockfile."""
    target_pkgs = packages or LOCKED_PACKAGES
    print(f"[*] Fetching PyPI release hashes for {len(target_pkgs)} packages using {workers} worker threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch_package_hashes, pkg, timeout) for pkg in target_pkgs]
        results = [f.result() for f in futures]

    errors = [f"{name}=={ver}: {err}" for name, ver, _, err in results if err]
    if errors:
        print("[!] Encountered errors fetching package metadata:")
        for err in errors:
            print(f"    - {err}")
        return 1

    total_hashes = sum(len(set(h)) for _, _, h, _ in results)
    lock_text = build_lock_content(results)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(lock_text, encoding="utf-8")

    print(f"[+] Successfully generated lockfile at: {output_path}")
    print(f"[+] Total locked dependencies: {len(results)}, Total SHA-256 digests: {total_hashes}")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Generate requirements-lock.txt with multi-platform SHA-256 hashes for NetworkSentry.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=PROJECT_ROOT / "requirements-lock.txt",
        help="Target output path for the lock file (default: repository root requirements-lock.txt)",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=10,
        help="Number of concurrent thread workers for PyPI queries (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds per package (default: 15.0)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    return generate_lock_file(
        output_path=args.output,
        workers=args.workers,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    sys.exit(main())
