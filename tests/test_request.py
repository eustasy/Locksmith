"""Tests for the locksmith-request CLI (.lsreq generation).

The command is driven through Click's ``CliRunner`` so the option parsing, the
machine-ID lookup, and the file output are all exercised end-to-end.
``compute_machine_id`` is patched to a fixed value so assertions don't depend on
the host hardware.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import locksmith.cli.request as request_cli
from locksmith.core.license import LicenseRequest

FAKE_MACHINE_ID = "a" * 64


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fake_machine_id(monkeypatch) -> str:
    """Force ``compute_machine_id`` to a deterministic, host-independent value."""
    monkeypatch.setattr(request_cli, "compute_machine_id", lambda: FAKE_MACHINE_ID)
    return FAKE_MACHINE_ID


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_writes_request_with_all_fields(runner, fake_machine_id, tmp_path):
    out = tmp_path / "req.lsreq"
    result = runner.invoke(
        request_cli.main,
        [
            "--email", "user@co.com",
            "--app-id", "com.example.app",
            "--app-version", "2.1.0",
            "--out", str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()

    req = LicenseRequest.from_file(out)
    assert req.email == "user@co.com"
    assert req.app_id == "com.example.app"
    assert req.app_version == "2.1.0"
    assert req.machine_id == fake_machine_id
    assert req.requested_at is not None

    assert f"Machine ID: {fake_machine_id}" in result.output
    assert f"Request written to: {out}" in result.output
    assert "Send this file to your software vendor" in result.output


def test_default_output_filename_and_optional_app_id(runner, fake_machine_id):
    """With --out and --app-id omitted: filename is derived from the email, app_id is None."""
    with runner.isolated_filesystem():
        result = runner.invoke(
            request_cli.main,
            ["--email", "user@co.com", "--app-version", "2.1.0"],
        )
        assert result.exit_code == 0, result.output

        req = LicenseRequest.from_file("user_co_com.lsreq")
        assert req.email == "user@co.com"
        assert req.app_id is None
        assert req.app_version == "2.1.0"
        assert req.machine_id == fake_machine_id


# ---------------------------------------------------------------------------
# Machine-ID failure is non-fatal
# ---------------------------------------------------------------------------


def test_machine_id_failure_is_graceful(runner, monkeypatch, tmp_path):
    """A RuntimeError from compute_machine_id warns on stderr but still writes the file."""

    def _boom() -> str:
        raise RuntimeError("no machine id here")

    monkeypatch.setattr(request_cli, "compute_machine_id", _boom)

    out = tmp_path / "req.lsreq"
    result = runner.invoke(
        request_cli.main,
        ["--email", "user@co.com", "--app-version", "2.1.0", "--out", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert "could not compute machine ID" in result.stderr
    assert "no machine id here" in result.stderr

    req = LicenseRequest.from_file(out)
    assert req.machine_id is None
    assert req.email == "user@co.com"


# ---------------------------------------------------------------------------
# Required options
# ---------------------------------------------------------------------------


def test_email_is_required(runner):
    result = runner.invoke(request_cli.main, ["--app-version", "2.1.0"])
    assert result.exit_code != 0
    assert "--email" in result.stderr


def test_app_version_is_required(runner):
    result = runner.invoke(request_cli.main, ["--email", "user@co.com"])
    assert result.exit_code != 0
    assert "--app-version" in result.stderr
