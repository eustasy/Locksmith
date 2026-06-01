"""Tests for the locksmith-issue CLI (.lic generation and signing).

Each test signs through the real pipeline: the session keypair is written to PEM
files and ``settings`` is pointed at them, the command is driven via Click's
``CliRunner``, and the resulting ``.lic`` is loaded and validated with a
verify-only signer to prove it was signed correctly.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import locksmith.cli.generate as generate_cli
from locksmith.core.keys import FileSigner, save_keypair
from locksmith.core.license import License, LicenseRequest, RestrictionMode, TimePolicy, VersionPolicy
from locksmith.core.signer import validate_license


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def keyfiles(keypair, tmp_path, monkeypatch):
    """Write the session keypair to PEM files and point settings at them."""
    pub, priv = keypair
    privf, pubf = save_keypair(pub, priv, tmp_path / "keys")
    monkeypatch.setattr(generate_cli.settings, "pubkey_path", pubf)
    monkeypatch.setattr(generate_cli.settings, "privkey_path", privf)
    return pubf, privf


@pytest.fixture
def verify_signer(keypair) -> FileSigner:
    pub, _ = keypair
    return FileSigner(privkey=None, pubkey=pub)


def _validate(path, signer: FileSigner, **kwargs) -> License:
    """Load a written .lic and assert it validates; returns the License."""
    lic = License.from_file(path)
    asyncio.run(validate_license(lic, signer, **kwargs))
    return lic


# ---------------------------------------------------------------------------
# Basic issuance
# ---------------------------------------------------------------------------


def test_basic_perpetual(runner, keyfiles, verify_signer, tmp_path):
    out = tmp_path / "basic.lic"
    r = runner.invoke(generate_cli.main, ["--email", "user@co.com", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()

    lic = _validate(out, verify_signer)
    assert lic.email == "user@co.com"
    assert lic.time_policy == TimePolicy.PERPETUAL
    assert lic.restriction is None
    assert lic.entitlements == []

    assert f"License written to: {out}" in r.output
    assert "Time            : perpetual" in r.output
    assert "Editions        : any" in r.output
    assert "Platforms       : any" in r.output
    assert "Restriction     : none" in r.output
    assert "Entitlements    : none (applies to all applications)" in r.output


def test_default_output_filename(runner, keyfiles, verify_signer):
    with runner.isolated_filesystem():
        r = runner.invoke(generate_cli.main, ["--email", "user@co.com"])
        assert r.exit_code == 0, r.output
        # Default name is {safe_email}_{id8}.lic
        matches = list(Path().glob("user_co_com_*.lic"))
        assert len(matches) == 1
        assert _validate(matches[0], verify_signer).email == "user@co.com"


# ---------------------------------------------------------------------------
# Full option surface + single-app entitlement
# ---------------------------------------------------------------------------


def test_full_featured_single_entitlement(runner, keyfiles, verify_signer, tmp_path):
    out = tmp_path / "full.lic"
    r = runner.invoke(
        generate_cli.main,
        [
            "--email",
            "user@co.com",
            "--expires-days",
            "365",
            "--editions",
            "Pro, Enterprise",  # CSV split + trimmed + lowercased
            "--platforms",
            "windows, linux",
            "--restriction",
            "activations",
            "--activation-limit",
            "3",
            "--app-id",
            "com.example.app",
            "--entitlement-editions",
            "pro",
            "--entitlement-min-version",
            "2.0.0",
            "--entitlement-max-version",
            "2.9.9",
            "--entitlement-platforms",
            "windows",
            "--entitlement-seats",
            "5",
            "--out",
            str(out),
        ],
    )
    assert r.exit_code == 0, r.output

    lic = _validate(out, verify_signer, app_id="com.example.app", app_version="2.5.0", edition="pro", platform="windows")
    assert lic.time_policy == TimePolicy.LIMITED
    assert lic.expires_at is not None
    assert lic.editions == ["pro", "enterprise"]
    assert lic.platforms == ["windows", "linux"]
    assert lic.activation_limit == 3

    ent = lic.entitlements[0]
    assert ent.app_id == "com.example.app"
    assert ent.editions == ["pro"]
    assert ent.min_version == "2.0.0"
    assert ent.max_version == "2.9.9"
    assert ent.platforms == ["windows"]
    assert ent.seats == 5

    assert "Restriction     : activations (limit: 3)" in r.output
    assert "Entitlements    : 1 app(s)" in r.output
    assert "[com.example.app] editions=pro versions=2.0.0..2.9.9 platforms=windows seats=5" in r.output


def test_floating_restriction_summary(runner, keyfiles, verify_signer, tmp_path):
    out = tmp_path / "float.lic"
    r = runner.invoke(
        generate_cli.main,
        ["--email", "u@co.com", "--restriction", "floating", "--concurrent-limit", "10", "--out", str(out)],
    )
    assert r.exit_code == 0, r.output
    lic = _validate(out, verify_signer)
    assert lic.restriction == RestrictionMode.FLOATING
    assert lic.concurrent_limit == 10
    assert "Restriction     : floating (limit: 10)" in r.output


# ---------------------------------------------------------------------------
# Version policies (covers _format_version branches)
# ---------------------------------------------------------------------------


def test_maintenance_version_policy(runner, keyfiles, verify_signer, tmp_path):
    out = tmp_path / "maint.lic"
    r = runner.invoke(
        generate_cli.main,
        ["--email", "u@co.com", "--version-policy", "maintenance", "--major-version", "2", "--out", str(out)],
    )
    assert r.exit_code == 0, r.output
    lic = _validate(out, verify_signer, app_version="2.5.0")
    assert lic.version_policy == VersionPolicy.MAINTENANCE
    assert lic.major_version == 2
    assert "Version         : maintenance (major 2)" in r.output


def test_specific_version_policy(runner, keyfiles, verify_signer, tmp_path):
    out = tmp_path / "spec.lic"
    r = runner.invoke(
        generate_cli.main,
        ["--email", "u@co.com", "--version-policy", "specific", "--locked-version", "2.3.1", "--out", str(out)],
    )
    assert r.exit_code == 0, r.output
    lic = _validate(out, verify_signer, app_version="2.3.1")
    assert lic.version_policy == VersionPolicy.SPECIFIC
    assert lic.locked_version == "2.3.1"
    assert "Version         : specific (locked 2.3.1)" in r.output


# ---------------------------------------------------------------------------
# Request-file import
# ---------------------------------------------------------------------------


def test_import_from_request_file(runner, keyfiles, verify_signer, tmp_path):
    req = LicenseRequest.new(email="customer@co.com", machine_id="m-hash", app_version="1.0.0", app_id="com.example.app")
    reqf = tmp_path / "req.lsreq"
    req.to_file(reqf)

    out = tmp_path / "fromreq.lic"
    r = runner.invoke(generate_cli.main, ["--request-file", str(reqf), "--out", str(out)])
    assert r.exit_code == 0, r.output

    # email and app_id are imported from the request → one entitlement
    lic = _validate(out, verify_signer, app_id="com.example.app", app_version="1.0.0")
    assert lic.email == "customer@co.com"
    assert [e.app_id for e in lic.entitlements] == ["com.example.app"]
    assert "Email           : customer@co.com" in r.output


# ---------------------------------------------------------------------------
# Entitlements bundle file
# ---------------------------------------------------------------------------


def test_entitlements_file_bundle(runner, keyfiles, verify_signer, tmp_path):
    bundle = [
        {"app_id": "com.example.app1", "seats": 2},
        {"app_id": "com.example.app2", "platforms": ["macos"], "seats": 5},
    ]
    bundlef = tmp_path / "bundle.json"
    bundlef.write_text(json.dumps(bundle), encoding="utf-8")

    out = tmp_path / "bundle.lic"
    r = runner.invoke(
        generate_cli.main,
        ["--email", "user@co.com", "--entitlements-file", str(bundlef), "--out", str(out)],
    )
    assert r.exit_code == 0, r.output

    lic = _validate(out, verify_signer, app_id="com.example.app2", app_version="1.0.0", platform="macos")
    assert {e.app_id for e in lic.entitlements} == {"com.example.app1", "com.example.app2"}
    assert "Entitlements    : 2 app(s)" in r.output


def test_entitlements_file_must_be_array(runner, keyfiles, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"app_id": "not-a-list"}), encoding="utf-8")
    r = runner.invoke(generate_cli.main, ["--email", "user@co.com", "--entitlements-file", str(bad)])
    assert r.exit_code != 0
    assert "must contain a JSON array" in r.stderr


# ---------------------------------------------------------------------------
# Key source + required options
# ---------------------------------------------------------------------------


def test_explicit_privkey_flag(runner, keypair, verify_signer, tmp_path, monkeypatch):
    """--privkey overrides settings.privkey_path (which is left unset here)."""
    pub, priv = keypair
    privf, pubf = save_keypair(pub, priv, tmp_path / "keys")
    monkeypatch.setattr(generate_cli.settings, "pubkey_path", pubf)  # only the pubkey via settings

    out = tmp_path / "x.lic"
    r = runner.invoke(generate_cli.main, ["--email", "u@co.com", "--privkey", str(privf), "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert _validate(out, verify_signer).email == "u@co.com"


def test_email_required_without_request_file(runner):
    r = runner.invoke(generate_cli.main, [])
    assert r.exit_code != 0
    assert "--email is required" in r.stderr
