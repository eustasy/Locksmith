"""Tests for the locksmith-setup CLI (RSA keypair generation).

Real key generation uses small (1024-bit) keys to stay fast — 1024 is the
smallest size that still supports the SHA-512 sign/verify roundtrip used to
prove the generated pair is usable. The wiring test patches out generation
entirely and reuses the session keypair.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from click.testing import CliRunner

import locksmith.cli.setup as setup_cli
from locksmith.core.keys import FileSigner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_generates_loadable_keypair(runner, tmp_path):
    out_dir = tmp_path / "keys"
    result = runner.invoke(setup_cli.main, ["--bits", "1024", "--out-dir", str(out_dir)])
    assert result.exit_code == 0, result.output

    priv = out_dir / "privkey.pem"
    pub = out_dir / "pubkey.pem"
    assert priv.exists()
    assert pub.exists()

    # Output reports the size, both paths, and the secret-key warning.
    assert "Generating 1024-bit RSA keypair" in result.output
    assert f"Private key : {priv}" in result.output
    assert f"Public key  : {pub}" in result.output
    assert "Never commit it to source control." in result.output

    # The generated pair is cryptographically usable end-to-end.
    signer = FileSigner.from_files(pubkey_path=pub, privkey_path=priv)
    sig = asyncio.run(signer.sign(b"payload"))
    assert asyncio.run(signer.verify(b"payload", sig)) is True


def test_default_out_dir_is_keys(runner):
    with runner.isolated_filesystem():
        result = runner.invoke(setup_cli.main, ["--bits", "1024"])
        assert result.exit_code == 0, result.output
        assert Path("keys/privkey.pem").exists()
        assert Path("keys/pubkey.pem").exists()


def test_bits_and_out_dir_forwarded(runner, keypair, monkeypatch):
    """--bits reaches generate_keypair and --out-dir reaches save_keypair (generation stubbed out)."""
    captured: dict = {}

    def _fake_generate(bits):
        captured["bits"] = bits
        return keypair  # reuse the session keypair; skip slow keygen

    def _fake_save(pubkey, privkey, out_dir):
        captured["out_dir"] = out_dir
        captured["pubkey"] = pubkey
        captured["privkey"] = privkey
        return f"{out_dir}/privkey.pem", f"{out_dir}/pubkey.pem"

    monkeypatch.setattr(setup_cli, "generate_keypair", _fake_generate)
    monkeypatch.setattr(setup_cli, "save_keypair", _fake_save)

    result = runner.invoke(setup_cli.main, ["--bits", "2048", "--out-dir", "vault/keys"])
    assert result.exit_code == 0, result.output

    pub, priv = keypair
    assert captured["bits"] == 2048
    assert captured["out_dir"] == "vault/keys"
    assert captured["pubkey"] is pub
    assert captured["privkey"] is priv
    assert "Generating 2048-bit RSA keypair" in result.output
