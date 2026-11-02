"""Centralized logging and application data directory configuration for Network Sentry."""

import logging
import os
import shutil
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Optional

_FILE_HANDLERS: Dict[str, RotatingFileHandler] = {}


def get_app_data_dir() -> Path:
    """
    Return a writable, absolute per-user application data directory
    (e.g., `%LOCALAPPDATA%\\NetworkSentry` on Windows or `~/.local/share/NetworkSentry` on Linux).
    """
    override = os.environ.get("NETWORKSENTRY_DATA_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32" or os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if local_app_data:
            base = Path(local_app_data) / "NetworkSentry"
        else:
            base = Path.home() / "AppData" / "Local" / "NetworkSentry"
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            base = Path(xdg_data) / "NetworkSentry"
        else:
            base = Path.home() / ".local" / "share" / "NetworkSentry"

    try:
        base.mkdir(parents=True, exist_ok=True)
        return base.resolve()
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "NetworkSentry"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback.resolve()


def resolve_data_path(path: str | Path, seed_from_bundle: bool = False) -> Path:
    """
    Convert a relative application file path (like `networksentry.log` or `networksentry.db`)
    into an absolute path inside `get_app_data_dir()`. Absolute paths are returned as-is.
    """
    p = Path(path)
    if p.is_absolute():
        return p

    target = get_app_data_dir() / p
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    if seed_from_bundle and not target.exists():
        candidates = []
        if getattr(sys, "frozen", False):
            candidates.append(Path(sys.executable).resolve().parent / p.name)
        candidates.append(Path(__file__).resolve().parents[2] / p.name)
        for cand in candidates:
            try:
                if cand.exists() and cand.resolve() != target.resolve():
                    shutil.copy2(cand, target)
                    break
            except OSError:
                continue

    return target


def setup_logger(
    name: str = "NetworkSentry",
    log_file: Optional[str | Path] = "networksentry.log",
    level: int = logging.INFO,
) -> logging.Logger:
    """Configure and return a thread-safe application logger using a writable absolute log path."""
    logger = logging.getLogger(name)
    effective_level = min(level, logging.DEBUG) if log_file else level
    if logger.handlers:
        logger.setLevel(effective_level)
        return logger

    logger.setLevel(effective_level)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if sys.stdout is not None:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if log_file:
        log_path = resolve_data_path(log_file)
        norm_key = str(log_path).lower()
        file_handler = _FILE_HANDLERS.get(norm_key)
        if file_handler is None:
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = RotatingFileHandler(
                    log_path,
                    maxBytes=5 * 1024 * 1024,
                    backupCount=3,
                    encoding="utf-8",
                )
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                _FILE_HANDLERS[norm_key] = file_handler
            except OSError:
                try:
                    fallback_path = Path(tempfile.gettempdir()) / "NetworkSentry" / Path(log_file).name
                    fallback_path.parent.mkdir(parents=True, exist_ok=True)
                    file_handler = RotatingFileHandler(
                        fallback_path,
                        maxBytes=5 * 1024 * 1024,
                        backupCount=3,
                        encoding="utf-8",
                    )
                    file_handler.setLevel(logging.DEBUG)
                    file_handler.setFormatter(formatter)
                    _FILE_HANDLERS[norm_key] = file_handler
                except OSError:
                    file_handler = None

        if file_handler is not None:
            logger.addHandler(file_handler)

    return logger


