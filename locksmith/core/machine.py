"""Cross-platform stable machine identifier.

Returns a SHA-256 hex digest (64 chars) derived from hardware/OS identifiers.
Supported platforms: Linux, Windows, macOS.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

try:
    import winreg  # type: ignore[attr-defined]
except ImportError:
    winreg = None


def _get_machine_id_linux() -> str:
    sources: list[str] = []

    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as f:
                sources.append(f.read().strip())
            break
        except OSError:
            pass  # File not found or unreadable; try next path

    for path in ("/bin", "/etc", "/lib", "/root", "/sbin", "/usr", "/var"):
        try:
            sources.append(str(os.stat(path).st_ino))
        except OSError:
            pass  # Directory inode unavailable; skip this source

    return "".join(sources)


def _get_machine_id_windows() -> str:
    try:
        if winreg is not None:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            if value:
                return str(value)
    except OSError:
        pass  # Registry key unavailable; fall back to wmic

    try:
        result = subprocess.run(
            ["wmic", "csproduct", "get", "UUID"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            return lines[1]
    except (OSError, subprocess.SubprocessError):
        pass  # wmic unavailable or failed; return empty string

    return ""


def _get_machine_id_macos() -> str:
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().strip('"')
    except (OSError, subprocess.SubprocessError):
        pass  # ioreg unavailable or failed; return empty string

    return ""


def compute_machine_id() -> str:
    """Return a stable SHA-256 hex digest identifying this machine (64 hex chars)."""
    platform = sys.platform

    if platform.startswith("win"):
        raw = _get_machine_id_windows()
    elif platform == "darwin":
        raw = _get_machine_id_macos()
    else:
        raw = _get_machine_id_linux()

    if not raw:
        raise RuntimeError(f"Unable to determine machine ID on platform '{platform}'.")

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
