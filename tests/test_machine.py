"""Tests for cross-platform machine ID computation."""

import locksmith.core.machine as machine
from locksmith.core.machine import compute_machine_id


def test_returns_nonempty_sha256_hex():
    result = compute_machine_id()
    assert isinstance(result, str), "machine ID should be a string"
    assert len(result) == 64, "SHA-256 hex digest should be 64 characters"
    int(result, 16)  # raises ValueError if not valid hex


def test_stable_across_calls():
    assert compute_machine_id() == compute_machine_id()


def test_windows_falls_back_to_empty_if_wmic_unavailable(monkeypatch):
    monkeypatch.setattr(machine, "winreg", None)

    def _raise_oserror(*_args, **_kwargs):
        raise OSError("wmic not found")

    monkeypatch.setattr(machine.subprocess, "run", _raise_oserror)

    assert machine._get_machine_id_windows() == ""


def test_macos_returns_empty_if_ioreg_fails(monkeypatch):
    def _raise_subprocess_error(*_args, **_kwargs):
        raise machine.subprocess.SubprocessError("ioreg failed")

    monkeypatch.setattr(machine.subprocess, "run", _raise_subprocess_error)

    assert machine._get_machine_id_macos() == ""
