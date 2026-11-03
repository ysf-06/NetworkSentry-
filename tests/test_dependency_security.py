"""Unit tests for dependency security, version locking, and hash verification."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import pytest

# Repository root
REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_TXT = REPO_ROOT / "requirements.txt"
REQUIREMENTS_LOCK_TXT = REPO_ROOT / "requirements-lock.txt"
SCRIPTS_GENERATE_LOCK = REPO_ROOT / "scripts" / "generate_requirements_lock.py"


def parse_lock_file(lock_path: Path) -> dict[str, dict[str, object]]:
    """Parse requirements-lock.txt into package entries and their hashes."""
    text = lock_path.read_text(encoding="utf-8")
    entries: dict[str, dict[str, object]] = {}

    current_pkg: str | None = None
    current_ver: str | None = None
    current_hashes: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip trailing line continuation
        if line.endswith("\\"):
            line = line[:-1].strip()

        if line.startswith("--hash=sha256:"):
            digest = line.split(":", 1)[1].strip()
            current_hashes.append(digest)
        elif "==" in line:
            # If we were tracking a previous package, save it
            if current_pkg and current_ver:
                entries[current_pkg.lower()] = {
                    "package": current_pkg,
                    "version": current_ver,
                    "hashes": list(current_hashes),
                }
            pkg_part = line.split()[0]
            name, ver = pkg_part.split("==", 1)
            current_pkg = name.strip()
            current_ver = ver.strip()
            current_hashes = []
            # Check if hash is on the same line
            if "--hash=sha256:" in line:
                for part in line.split():
                    if part.startswith("--hash=sha256:"):
                        current_hashes.append(part.split(":", 1)[1].strip())

    if current_pkg and current_ver:
        entries[current_pkg.lower()] = {
            "package": current_pkg,
            "version": current_ver,
            "hashes": list(current_hashes),
        }

    return entries


def test_requirements_lock_file_exists() -> None:
    """Verify that requirements-lock.txt exists at repository root and is populated."""
    assert REQUIREMENTS_LOCK_TXT.exists(), "requirements-lock.txt must exist at repository root"
    content = REQUIREMENTS_LOCK_TXT.read_text(encoding="utf-8")
    assert len(content.strip()) > 1000, "requirements-lock.txt must not be empty"


def test_every_requirement_pinned_with_strict_equality() -> None:
    """Verify that every requirement has exact == pinning and valid sha256 hashes."""
    entries = parse_lock_file(REQUIREMENTS_LOCK_TXT)
    assert len(entries) >= 49, f"Expected at least 49 locked packages, found {len(entries)}"

    sha256_regex = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

    for norm_name, data in entries.items():
        ver = data["version"]
        assert isinstance(ver, str) and ver, f"Package {norm_name} has invalid version: {ver}"
        assert not any(op in ver for op in (">", "<", "~", "*", "^")), (
            f"Package {norm_name} contains non-pinned version specifier: {ver}"
        )

        hashes = data["hashes"]
        assert isinstance(hashes, list) and len(hashes) > 0, (
            f"Package {norm_name} must have at least one SHA-256 hash"
        )
        for h in hashes:
            assert sha256_regex.match(h), f"Invalid SHA-256 digest format for {norm_name}: {h}"


def test_all_direct_dependencies_from_requirements_txt_included() -> None:
    """Verify that all direct dependencies declared in requirements.txt are locked."""
    assert REQUIREMENTS_TXT.exists(), "requirements.txt must exist"
    req_lines = REQUIREMENTS_TXT.read_text(encoding="utf-8").splitlines()

    direct_pkgs: list[str] = []
    for line in req_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Extract package name before any operator
        m = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if m:
            direct_pkgs.append(m.group(1).lower().replace("-", "_"))

    assert len(direct_pkgs) >= 8, f"Expected at least 8 direct requirements, found {len(direct_pkgs)}"

    entries = parse_lock_file(REQUIREMENTS_LOCK_TXT)
    normalized_locked = {k.replace("-", "_"): v for k, v in entries.items()}

    for direct in direct_pkgs:
        assert direct in normalized_locked, (
            f"Direct requirement '{direct}' from requirements.txt is missing in requirements-lock.txt"
        )


def test_transitive_critical_dependencies_present() -> None:
    """Verify essential transitive dependencies required for clean installs are present."""
    entries = parse_lock_file(REQUIREMENTS_LOCK_TXT)
    normalized_keys = {k.replace("-", "_") for k in entries.keys()}

    critical_transitives = [
        "filelock",
        "pip",
        "pip_api",
        "shiboken6",
        "coverage",
        "typing_extensions",
        "packaging",
        "requests",
        "urllib3",
    ]

    for crit in critical_transitives:
        assert crit in normalized_keys, (
            f"Critical transitive dependency '{crit}' missing from requirements-lock.txt"
        )


def test_multi_platform_hashes_present() -> None:
    """Verify that binary packages include multiple distribution hashes across platforms."""
    entries = parse_lock_file(REQUIREMENTS_LOCK_TXT)
    normalized = {k.replace("-", "_"): v for k, v in entries.items()}

    multi_platform_checks = ["psutil", "pyside6", "ruff", "mypy"]
    for pkg in multi_platform_checks:
        assert pkg in normalized, f"Package {pkg} must be present in lockfile"
        hashes = normalized[pkg]["hashes"]
        assert isinstance(hashes, list)
        assert len(hashes) >= 4, (
            f"Package {pkg} must have multi-platform hashes (found {len(hashes)}, expected >= 4)"
        )


def test_generate_lock_script_structure() -> None:
    """Verify that scripts/generate_requirements_lock.py exists and generates valid content."""
    assert SCRIPTS_GENERATE_LOCK.exists(), "scripts/generate_requirements_lock.py must exist"

    # Verify build_lock_content function
    sys.path.insert(0, str(REPO_ROOT))
    from scripts.generate_requirements_lock import build_lock_content

    dummy_results: list[tuple[str, str, Sequence[str], str | None]] = [
        ("demo-pkg", "1.0.0", ["a" * 64, "b" * 64], None),
    ]
    formatted = build_lock_content(dummy_results)
    assert "demo-pkg==1.0.0" in formatted
    assert f"--hash=sha256:{'a' * 64}" in formatted
    assert f"--hash=sha256:{'b' * 64}" in formatted


def test_pip_audit_exit_code_zero() -> None:
    """Verify that pip-audit passes on requirements-lock.txt with zero vulnerabilities."""
    pip_audit_exe = shutil.which("pip-audit")
    if not pip_audit_exe:
        # Check standard venv location
        candidate = REPO_ROOT / ".venv" / "Scripts" / "pip-audit.exe"
        if candidate.exists():
            pip_audit_exe = str(candidate)

    if not pip_audit_exe:
        pytest.skip("pip-audit executable not found in PATH or .venv")

    cmd = [
        pip_audit_exe,
        "-r",
        str(REQUIREMENTS_LOCK_TXT),
        "--require-hashes",
        "--disable-pip",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, (
        f"pip-audit failed with exit code {proc.returncode}.\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    )
    assert "No known vulnerabilities found" in proc.stderr or "No known vulnerabilities found" in proc.stdout, (
        f"Unexpected pip-audit output:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    )
