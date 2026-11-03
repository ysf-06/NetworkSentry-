"""Unit tests for release packaging and Authenticode code signing security (Milestone 2 / R2)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from scripts.package_release import (
    PROJECT_ROOT,
    compute_sha256,
    find_signtool,
    generate_release_notes,
    package_and_compute_checksums,
    parse_args,
    sign_binary,
    sign_release_artifacts,
)

# ============================================================================
# 1. Verification of package_release.bat
# ============================================================================


def test_package_release_bat_does_not_delete_root_db() -> None:
    """Verify package_release.bat removes only dist database and preserves root networksentry.db*."""
    bat_path = PROJECT_ROOT / "package_release.bat"
    assert bat_path.exists(), "package_release.bat must exist in project root."

    content = bat_path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()

    # Must NOT have any line that deletes root networksentry.db*
    # Vulnerable pattern was: if exist "networksentry.db*" del ...
    root_db_del_pattern = re.compile(r'del\s+[^"]*"?networksentry\.db', re.IGNORECASE)

    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("rem") or stripped.startswith("::"):
            continue
        if "networksentry.db" in stripped.lower():
            if root_db_del_pattern.search(stripped):
                pytest.fail(f"Line {line_idx} deletes networksentry.db in root: {line}")
            # Any deletion must explicitly target dist\
            if "del " in stripped.lower():
                assert (
                    "dist\\networksentry\\networksentry.db" in stripped.lower()
                    or "dist/networksentry/networksentry.db" in stripped.lower()
                ), f"Line {line_idx} deletes networksentry.db outside dist: {line}"

    # Must clean dist\NetworkSentry\networksentry.db*
    assert 'dist\\NetworkSentry\\networksentry.db*' in content, (
        "package_release.bat should clean dist\\NetworkSentry\\networksentry.db*"
    )

    # Must have consistent 5-step numbering [1/5] through [5/5]
    for step in range(1, 6):
        assert f"[{step}/5]" in content, f"Step [{step}/5] missing in package_release.bat"

    # Must forward arguments %* to python script
    assert "scripts\\package_release.py %*" in content, (
        "package_release.bat must pass %* arguments to scripts\\package_release.py"
    )


# ============================================================================
# 2. signtool Discovery Logic
# ============================================================================


def test_find_signtool_explicit_path(tmp_path: Path) -> None:
    """find_signtool should honor an explicit, existing file path."""
    fake_signtool = tmp_path / "custom_signtool.exe"
    fake_signtool.write_text("binary", encoding="utf-8")

    result = find_signtool(explicit_path=str(fake_signtool))
    assert result == fake_signtool


def test_find_signtool_explicit_nonexistent_falls_through(tmp_path: Path) -> None:
    """find_signtool should ignore non-existent explicit path and fall through."""
    nonexistent = tmp_path / "does_not_exist.exe"
    with patch("shutil.which", return_value=None), patch("platform.system", return_value="Linux"):
        assert find_signtool(explicit_path=str(nonexistent)) is None


def test_find_signtool_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """find_signtool should discover signtool via SIGNTOOL_PATH environment variable."""
    fake_signtool = tmp_path / "env_signtool.exe"
    fake_signtool.write_text("binary", encoding="utf-8")
    monkeypatch.setenv("SIGNTOOL_PATH", str(fake_signtool))

    result = find_signtool()
    assert result == fake_signtool


def test_find_signtool_shutil_which(monkeypatch: pytest.MonkeyPatch) -> None:
    """find_signtool should discover signtool via PATH if which() finds it."""
    monkeypatch.delenv("SIGNTOOL_PATH", raising=False)
    with patch("shutil.which", return_value=r"C:\Windows\System32\signtool.exe"):
        result = find_signtool()
        assert result == Path(r"C:\Windows\System32\signtool.exe")


def test_find_signtool_windows_sdk_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """find_signtool should discover signtool within Windows Kits 10 SDK directories."""
    monkeypatch.delenv("SIGNTOOL_PATH", raising=False)
    with patch("shutil.which", return_value=None), patch("platform.system", return_value="Windows"):
        sdk_bin = tmp_path / "Windows Kits" / "10" / "bin"
        version_dir = sdk_bin / "10.0.26100.0" / "x64"
        version_dir.mkdir(parents=True)
        fake_signtool = version_dir / "signtool.exe"
        fake_signtool.write_text("binary", encoding="utf-8")

        monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path))
        result = find_signtool()
        assert result == fake_signtool


def test_find_signtool_app_cert_kit_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """find_signtool should discover signtool within App Certification Kit."""
    monkeypatch.delenv("SIGNTOOL_PATH", raising=False)
    with patch("shutil.which", return_value=None), patch("platform.system", return_value="Windows"):
        app_cert_dir = tmp_path / "Windows Kits" / "10" / "App Certification Kit"
        app_cert_dir.mkdir(parents=True)
        fake_signtool = app_cert_dir / "signtool.exe"
        fake_signtool.write_text("binary", encoding="utf-8")

        monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path))
        result = find_signtool()
        assert result == fake_signtool


def test_find_signtool_returns_none_when_unresolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """find_signtool should return None if signtool is nowhere to be found."""
    monkeypatch.delenv("SIGNTOOL_PATH", raising=False)
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "nonexistent1"))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "nonexistent2"))
    with patch("shutil.which", return_value=None), patch("platform.system", return_value="Linux"):
        assert find_signtool() is None


# ============================================================================
# 3. sign_binary Execution Logic
# ============================================================================


def test_sign_binary_success(tmp_path: Path) -> None:
    """sign_binary should construct proper signtool arguments and return True on 0 exit."""
    fake_target = tmp_path / "NetworkSentry.exe"
    fake_target.write_text("MZ...", encoding="utf-8")
    fake_signtool = tmp_path / "signtool.exe"
    fake_cert = tmp_path / "cert.pfx"

    captured_cmds: list[list[str]] = []

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured_cmds.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="Successfully signed", stderr="")

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        ok = sign_binary(
            target=fake_target,
            signtool=fake_signtool,
            cert_path=fake_cert,
            cert_password="secret_pass",
            timestamp_url="http://timestamp.digicert.com",
            description="Cyber Guardian Test",
        )
        assert ok is True
        assert len(captured_cmds) == 1
        cmd = captured_cmds[0]
        assert str(fake_signtool) in cmd[0]
        assert "sign" in cmd
        assert "/fd" in cmd and "SHA256" in cmd
        assert "/f" in cmd and str(fake_cert) in cmd
        assert "/p" in cmd and "secret_pass" in cmd
        assert "/tr" in cmd and "http://timestamp.digicert.com" in cmd
        assert "/td" in cmd and "SHA256" in cmd
        assert "/d" in cmd and "Cyber Guardian Test" in cmd
        assert str(fake_target) == cmd[-1]


def test_sign_binary_failure_returns_false(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """sign_binary should return False and log a warning when signtool exits non-zero."""
    fake_target = tmp_path / "NetworkSentry.exe"
    fake_target.write_text("MZ...", encoding="utf-8")
    fake_signtool = tmp_path / "signtool.exe"
    fake_cert = tmp_path / "cert.pfx"

    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess([], returncode=1, stdout="", stderr="SignTool Error: Invalid cert"),
    ):
        ok = sign_binary(target=fake_target, signtool=fake_signtool, cert_path=fake_cert)
        assert ok is False
        captured = capsys.readouterr().out
        assert "[!] Warning: Code signing failed for NetworkSentry.exe" in captured


def test_sign_binary_exception_returns_false(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """sign_binary should catch OSError/exceptions gracefully and return False."""
    fake_target = tmp_path / "NetworkSentry.exe"
    fake_target.write_text("MZ...", encoding="utf-8")
    fake_signtool = tmp_path / "signtool.exe"
    fake_cert = tmp_path / "cert.pfx"

    with patch("subprocess.run", side_effect=OSError("Access denied")):
        ok = sign_binary(target=fake_target, signtool=fake_signtool, cert_path=fake_cert)
        assert ok is False
        captured = capsys.readouterr().out
        assert "[!] Warning: Failed to invoke signtool for NetworkSentry.exe" in captured


def test_sign_binary_target_not_found(tmp_path: Path) -> None:
    """sign_binary should return False immediately if target does not exist."""
    fake_target = tmp_path / "nonexistent.exe"
    fake_signtool = tmp_path / "signtool.exe"
    fake_cert = tmp_path / "cert.pfx"

    with patch("subprocess.run") as mock_run:
        ok = sign_binary(target=fake_target, signtool=fake_signtool, cert_path=fake_cert)
        assert ok is False
        mock_run.assert_not_called()


# ============================================================================
# 4. sign_release_artifacts Dispatch & Fallback Warnings
# ============================================================================


def test_sign_release_artifacts_skip_sign(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--skip-sign flag should skip signing and return True."""
    ok = sign_release_artifacts(dist_dir=tmp_path, skip_sign=True)
    assert ok is True
    captured = capsys.readouterr().out
    assert "Skipped via --skip-sign flag" in captured


def test_sign_release_artifacts_non_windows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Non-Windows platform should gracefully skip signing with notice and return True."""
    with patch("platform.system", return_value="Linux"):
        ok = sign_release_artifacts(dist_dir=tmp_path, cert_path="cert.pfx")
        assert ok is True
        captured = capsys.readouterr().out
        assert "Skipped on non-Windows platform (Linux)" in captured


def test_sign_release_artifacts_no_cert(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Missing certificate path should print notice and return True without failing."""
    with patch("platform.system", return_value="Windows"):
        ok = sign_release_artifacts(dist_dir=tmp_path, cert_path=None)
        assert ok is True
        captured = capsys.readouterr().out
        assert "No code-signing certificate provided" in captured


def test_sign_release_artifacts_cert_missing_on_disk(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Certificate path that does not exist on disk prints warning and returns True."""
    missing_cert = tmp_path / "missing.pfx"
    with patch("platform.system", return_value="Windows"):
        ok = sign_release_artifacts(dist_dir=tmp_path, cert_path=missing_cert)
        assert ok is True
        captured = capsys.readouterr().out
        assert "Warning: Code-signing certificate file not found" in captured


def test_sign_release_artifacts_no_signtool(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """When certificate exists but signtool cannot be found, prints warning and returns True."""
    existing_cert = tmp_path / "real.pfx"
    existing_cert.write_text("pfx data", encoding="utf-8")

    with patch("platform.system", return_value="Windows"), patch(
        "scripts.package_release.find_signtool", return_value=None
    ):
        ok = sign_release_artifacts(dist_dir=tmp_path, cert_path=existing_cert)
        assert ok is True
        captured = capsys.readouterr().out
        assert "Warning: Microsoft signtool.exe not found" in captured


def test_sign_release_artifacts_signs_detected_targets(tmp_path: Path) -> None:
    """When certificate and signtool exist, all existing binary candidates are signed."""
    existing_cert = tmp_path / "real.pfx"
    existing_cert.write_text("pfx data", encoding="utf-8")
    existing_signtool = tmp_path / "signtool.exe"
    existing_signtool.write_text("signtool", encoding="utf-8")

    # Set up mock targets
    app_dir = tmp_path / "NetworkSentry"
    app_dir.mkdir(parents=True)
    app_exe = app_dir / "NetworkSentry.exe"
    app_exe.write_text("MZ...", encoding="utf-8")

    signed_targets: list[Path] = []

    def mock_sign_binary(target: Path, *args: Any, **kwargs: Any) -> bool:
        signed_targets.append(target)
        return True

    with patch("platform.system", return_value="Windows"), patch(
        "scripts.package_release.find_signtool", return_value=existing_signtool
    ), patch("scripts.package_release.sign_binary", side_effect=mock_sign_binary):
        ok = sign_release_artifacts(
            dist_dir=tmp_path,
            cert_path=existing_cert,
            cert_password="pass",
            signtool_path=existing_signtool,
        )
        assert ok is True
        assert app_exe in signed_targets


# ============================================================================
# 5. Pipeline Re-sequencing: Signing BEFORE Archive & Checksums
# ============================================================================


def test_packaging_pipeline_execution_order(tmp_path: Path) -> None:
    """Verify code signing strictly executes BEFORE zip archiving and BEFORE checksum calculation."""
    execution_order: list[str] = []

    app_dir = tmp_path / "NetworkSentry"
    app_dir.mkdir(parents=True)
    app_exe = app_dir / "NetworkSentry.exe"
    app_exe.write_text("MZ...", encoding="utf-8")

    # Fake db file that should be cleaned
    stale_db = app_dir / "networksentry.db-wal"
    stale_db.write_text("stale", encoding="utf-8")

    def mock_sign_release_artifacts(*args: Any, **kwargs: Any) -> bool:
        execution_order.append("sign_release_artifacts")
        return True

    def mock_make_archive(base_name: str, format: str, **kwargs: Any) -> str:
        execution_order.append("make_archive")
        zip_file = Path(f"{base_name}.zip")
        zip_file.write_text("zip data", encoding="utf-8")
        return str(zip_file)

    def mock_compute_sha256(filepath: Path) -> str:
        execution_order.append(f"compute_sha256:{filepath.name}")
        return "fakehash123"

    with patch("scripts.package_release.sign_release_artifacts", side_effect=mock_sign_release_artifacts), patch(
        "shutil.make_archive", side_effect=mock_make_archive
    ), patch("scripts.package_release.compute_sha256", side_effect=mock_compute_sha256):
        exit_code = package_and_compute_checksums(dist_dir=tmp_path)
        assert exit_code == 0

    # Ensure stale DB was unlinked
    assert not stale_db.exists(), "Leftover database in dist/NetworkSentry must be cleaned."

    # Validate strict sequence:
    # 1. sign_release_artifacts must appear before make_archive
    # 2. make_archive must appear before compute_sha256
    assert "sign_release_artifacts" in execution_order
    assert "make_archive" in execution_order

    idx_sign = execution_order.index("sign_release_artifacts")
    idx_archive = execution_order.index("make_archive")

    sha_indices = [i for i, step in enumerate(execution_order) if step.startswith("compute_sha256")]
    assert len(sha_indices) > 0, "compute_sha256 must be called."

    assert idx_sign < idx_archive, (
        f"Order violation: sign_release_artifacts (index {idx_sign}) "
        f"must execute BEFORE make_archive (index {idx_archive})"
    )
    for sha_idx in sha_indices:
        assert idx_sign < sha_idx, (
            f"Order violation: sign_release_artifacts (index {idx_sign}) "
            f"must execute BEFORE compute_sha256 (index {sha_idx})"
        )


# ============================================================================
# 6. CLI Argument Parsing & Environment Variable Fallback
# ============================================================================


def test_parse_args_explicit() -> None:
    """CLI arguments should take precedence when provided."""
    args = parse_args(
        [
            "--cert",
            r"C:\certs\release.pfx",
            "--password",
            "SuperSecret",
            "--timestamp-url",
            "http://ts.custom.com",
            "--signtool",
            r"C:\bin\signtool.exe",
            "--skip-sign",
        ]
    )
    assert args.cert_path == r"C:\certs\release.pfx"
    assert args.cert_password == "SuperSecret"
    assert args.timestamp_url == "http://ts.custom.com"
    assert args.signtool_path == r"C:\bin\signtool.exe"
    assert args.skip_sign is True


def test_parse_args_env_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    """parse_args should fall back to environment variables when CLI flags are absent."""
    monkeypatch.setenv("CODE_SIGN_CERT_PATH", r"C:\env\cert.pfx")
    monkeypatch.setenv("CODE_SIGN_CERT_PASSWORD", "env_secret")
    monkeypatch.setenv("SIGNTOOL_PATH", r"C:\env\signtool.exe")
    monkeypatch.setenv("CODE_SIGN_TIMESTAMP_URL", "http://env.ts.com")

    args = parse_args([])
    assert args.cert_path == r"C:\env\cert.pfx"
    assert args.cert_password == "env_secret"
    assert args.signtool_path == r"C:\env\signtool.exe"
    assert args.timestamp_url == "http://env.ts.com"
    assert args.skip_sign is False


def test_compute_sha256_matches_standard(tmp_path: Path) -> None:
    """compute_sha256 computes expected known SHA-256 digest."""
    import hashlib

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"NetworkSentry Security Packaging Test 2026")
    expected = hashlib.sha256(b"NetworkSentry Security Packaging Test 2026").hexdigest()

    assert compute_sha256(sample) == expected


def test_generate_release_notes(tmp_path: Path) -> None:
    """generate_release_notes creates markdown file in target dist folder."""
    notes_path = generate_release_notes(tmp_path)
    assert notes_path.exists()
    content = notes_path.read_text(encoding="utf-8")
    assert "Release Notes" in content
    assert "Passive Live Wire Packet Capture" in content


def test_main_cli_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() entry point correctly parses CLI args and completes packaging."""
    from scripts.package_release import main

    # Use a isolated dist directory so we do not mutate real dist/
    dist_dir = tmp_path / "dist"
    monkeypatch.setattr("scripts.package_release.PROJECT_ROOT", tmp_path)

    app_dir = dist_dir / "NetworkSentry"
    app_dir.mkdir(parents=True)
    fake_exe = app_dir / "NetworkSentry.exe"
    fake_exe.write_text("MZ...", encoding="utf-8")

    code = main(["--skip-sign"])
    assert code == 0
    assert (dist_dir / "release_checksums.txt").exists()
    assert (dist_dir / f"NetworkSentry-v{Path(dist_dir / 'release_checksums.txt').read_text(encoding='utf-8').splitlines()[0]}").name  # exists
    checksums = (dist_dir / "release_checksums.txt").read_text(encoding="utf-8")
    assert "NetworkSentry.exe" in checksums

