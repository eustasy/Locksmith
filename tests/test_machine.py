"""Tests for cross-platform machine ID computation."""

import builtins
import hashlib

import pytest

import locksmith.core.machine as machine


def test_returns_nonempty_sha256_hex():
    result = machine.compute_machine_id()
    assert isinstance(result, str), "machine ID should be a string"
    assert len(result) == 64, "SHA-256 hex digest should be 64 characters"
    int(result, 16)  # raises ValueError if not valid hex


def test_stable_across_calls():
    assert machine.compute_machine_id() == machine.compute_machine_id()


def test_windows_falls_back_to_empty_if_wmic_unavailable(monkeypatch):
    monkeypatch.setattr(machine, "winreg", None)

    def _raise_os_error(*_args, **_kwargs):
        raise OSError("wmic not found")

    monkeypatch.setattr(machine.subprocess, "run", _raise_os_error)

    assert machine._get_machine_id_windows() == ""


def test_windows_falls_back_to_wmic_if_registry_unavailable(monkeypatch):
    class _MockWinreg:
        HKEY_LOCAL_MACHINE = object()

        @staticmethod
        def OpenKey(*_args, **_kwargs):
            raise OSError("registry unavailable")

    class _MockSubprocessResult:
        stdout = "UUID\nwmic-uuid\n"

    monkeypatch.setattr(machine, "winreg", _MockWinreg)
    monkeypatch.setattr(
        machine.subprocess,
        "run",
        lambda *_args, **_kwargs: _MockSubprocessResult(),
    )

    assert machine._get_machine_id_windows() == "wmic-uuid"


def test_macos_returns_empty_if_ioreg_fails(monkeypatch):
    def _raise_subprocess_error(*_args, **_kwargs):
        raise machine.subprocess.SubprocessError("ioreg failed")

    monkeypatch.setattr(machine.subprocess, "run", _raise_subprocess_error)

    assert machine._get_machine_id_macos() == ""


# ---------------------------------------------------------------------------
# Linux: both machine-id files unreadable → falls back to directory inodes
# ---------------------------------------------------------------------------


def test_linux_falls_back_to_inodes_when_machine_id_files_unreadable(monkeypatch):
    real_open = builtins.open

    def _open(path, *args, **kwargs):
        if str(path) in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            raise OSError("unreadable")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _open)

    result = machine._get_machine_id_linux()
    # No machine-id contributed, so the result is the concatenation of directory
    # inode numbers: non-empty on any normal filesystem and entirely digits.
    assert result != ""
    assert result.isdigit()


# ---------------------------------------------------------------------------
# Windows: registry success path
# ---------------------------------------------------------------------------


def test_windows_reads_machine_guid_from_registry(monkeypatch):
    class _MockWinreg:
        HKEY_LOCAL_MACHINE = object()

        @staticmethod
        def OpenKey(*_args, **_kwargs):
            return object()

        @staticmethod
        def QueryValueEx(_key, _name):
            return "REG-GUID-123", 1  # (value, type)

        @staticmethod
        def CloseKey(_key):
            pass

    monkeypatch.setattr(machine, "winreg", _MockWinreg)
    assert machine._get_machine_id_windows() == "REG-GUID-123"


# ---------------------------------------------------------------------------
# macOS: ioreg success path
# ---------------------------------------------------------------------------


def test_macos_parses_ioplatform_uuid(monkeypatch):
    class _Result:
        stdout = '    "IOPlatformUUID" = "MAC-UUID-123"\n    "other" = "x"\n'

    monkeypatch.setattr(machine.subprocess, "run", lambda *_a, **_k: _Result())
    assert machine._get_machine_id_macos() == "MAC-UUID-123"


# ---------------------------------------------------------------------------
# compute_machine_id: per-platform dispatch + failure
# ---------------------------------------------------------------------------


def test_compute_uses_windows_on_win32(monkeypatch):
    monkeypatch.setattr(machine.sys, "platform", "win32")
    monkeypatch.setattr(machine, "_get_machine_id_windows", lambda: "WIN-RAW")
    assert machine.compute_machine_id() == hashlib.sha256(b"WIN-RAW").hexdigest()


def test_compute_uses_macos_on_darwin(monkeypatch):
    monkeypatch.setattr(machine.sys, "platform", "darwin")
    monkeypatch.setattr(machine, "_get_machine_id_macos", lambda: "MAC-RAW")
    assert machine.compute_machine_id() == hashlib.sha256(b"MAC-RAW").hexdigest()


def test_compute_raises_when_no_identifier_found(monkeypatch):
    monkeypatch.setattr(machine.sys, "platform", "linux")
    monkeypatch.setattr(machine, "_get_machine_id_linux", lambda: "")
    with pytest.raises(RuntimeError, match="Unable to determine machine ID"):
        machine.compute_machine_id()
