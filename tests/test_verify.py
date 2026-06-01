"""Tests for the locksmith-verify CLI (offline .lic verification).

Each test signs a license to disk with a session keypair, writes the public key
to a PEM file, then drives the command through Click's ``CliRunner``. Valid
licenses exit 0 and print details; any ``LicenseError`` prints "INVALID" and
exits 1; Click guards (required / existing path) fail before the body runs.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from click.testing import CliRunner

import locksmith.cli.verify as verify_cli
from locksmith.core.keys import FileSigner, save_keypair
from locksmith.core.license import License, RestrictionMode, TimePolicy, VersionPolicy
from locksmith.core.signer import sign_license


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def pubkey_path(keypair, tmp_path):
    """Write the session keypair's public key to a PEM file and return its path."""
    pub, priv = keypair
    _privf, pubf = save_keypair(pub, priv, tmp_path / "keys")
    return pubf


@pytest.fixture
def signer(keypair) -> FileSigner:
    pub, priv = keypair
    return FileSigner(pubkey=pub, privkey=priv)


def _sign(signer: FileSigner, **overrides) -> License:
    """Build and sign a License with sensible, currently-valid defaults."""
    defaults = {
        "license_id": str(uuid.uuid4()),
        "email": "user@example.com",
        "issued_at": datetime.now(UTC),
        "valid_from": datetime.now(UTC) - timedelta(minutes=1),
        "time_policy": TimePolicy.PERPETUAL,
        "version_policy": VersionPolicy.ANY,
    }
    defaults.update(overrides)
    lic = License(**defaults)
    asyncio.run(sign_license(lic, signer))
    return lic


# ---------------------------------------------------------------------------
# Valid licenses
# ---------------------------------------------------------------------------


def test_valid_license_prints_details(runner, signer, pubkey_path, tmp_path):
    expires = datetime.now(UTC) + timedelta(days=30)
    lic = _sign(
        signer,
        time_policy=TimePolicy.LIMITED,
        expires_at=expires,
        restriction=RestrictionMode.ACTIVATIONS,
        activation_limit=3,
    )
    path = tmp_path / "ok.lic"
    lic.to_file(path)

    result = runner.invoke(verify_cli.main, ["--license", str(path), "--pubkey", str(pubkey_path)])
    assert result.exit_code == 0, result.output
    assert "License is VALID." in result.output
    assert f"ID              : {lic.license_id}" in result.output
    assert "Email           : user@example.com" in result.output
    assert "Time            : limited" in result.output
    assert "Version         : any" in result.output
    assert "Restriction     : activations" in result.output
    assert lic.expires_at.isoformat() in result.output


def test_valid_perpetual_shows_none_and_never(runner, signer, pubkey_path, tmp_path):
    """Perpetual, unrestricted license exercises the 'none' / 'never' display fallbacks."""
    lic = _sign(signer)  # perpetual, no restriction, no expiry
    path = tmp_path / "perp.lic"
    lic.to_file(path)

    result = runner.invoke(verify_cli.main, ["--license", str(path), "--pubkey", str(pubkey_path)])
    assert result.exit_code == 0, result.output
    assert "Restriction     : none" in result.output
    assert "Expires         : never" in result.output


def test_uses_settings_pubkey_when_flag_omitted(runner, signer, pubkey_path, tmp_path, monkeypatch):
    """With --pubkey omitted, the command falls back to settings.pubkey_path."""
    monkeypatch.setattr(verify_cli.settings, "pubkey_path", pubkey_path)
    lic = _sign(signer)
    path = tmp_path / "ok.lic"
    lic.to_file(path)

    result = runner.invoke(verify_cli.main, ["--license", str(path)])
    assert result.exit_code == 0, result.output
    assert "License is VALID." in result.output


# ---------------------------------------------------------------------------
# Invalid licenses (exit 1)
# ---------------------------------------------------------------------------


def test_tampered_license_is_invalid(runner, signer, pubkey_path, tmp_path):
    lic = _sign(signer)
    lic.email = "attacker@evil.com"  # mutate a signed field after signing
    path = tmp_path / "bad.lic"
    lic.to_file(path)

    result = runner.invoke(verify_cli.main, ["--license", str(path), "--pubkey", str(pubkey_path)])
    assert result.exit_code == 1
    assert "License is INVALID" in result.output


def test_expired_license_is_invalid(runner, signer, pubkey_path, tmp_path):
    lic = _sign(
        signer,
        time_policy=TimePolicy.LIMITED,
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    path = tmp_path / "exp.lic"
    lic.to_file(path)

    result = runner.invoke(verify_cli.main, ["--license", str(path), "--pubkey", str(pubkey_path)])
    assert result.exit_code == 1
    assert "License is INVALID" in result.output
    assert "expired" in result.output.lower()


def test_maintenance_needs_app_version(runner, signer, pubkey_path, tmp_path):
    lic = _sign(signer, version_policy=VersionPolicy.MAINTENANCE, major_version=2)
    path = tmp_path / "maint.lic"
    lic.to_file(path)

    # Without --app-version the maintenance policy can't be checked → invalid.
    r1 = runner.invoke(verify_cli.main, ["--license", str(path), "--pubkey", str(pubkey_path)])
    assert r1.exit_code == 1
    assert "License is INVALID" in r1.output

    # A matching --app-version validates.
    r2 = runner.invoke(
        verify_cli.main,
        ["--license", str(path), "--pubkey", str(pubkey_path), "--app-version", "2.5.0"],
    )
    assert r2.exit_code == 0, r2.output
    assert "License is VALID." in r2.output


# ---------------------------------------------------------------------------
# Click argument guards
# ---------------------------------------------------------------------------


def test_license_option_is_required(runner, pubkey_path):
    result = runner.invoke(verify_cli.main, ["--pubkey", str(pubkey_path)])
    assert result.exit_code != 0
    assert "--license" in result.stderr


def test_nonexistent_license_path_rejected(runner, pubkey_path, tmp_path):
    missing = tmp_path / "nope.lic"
    result = runner.invoke(verify_cli.main, ["--license", str(missing), "--pubkey", str(pubkey_path)])
    assert result.exit_code != 0
    assert "does not exist" in result.stderr
