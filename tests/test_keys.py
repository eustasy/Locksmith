"""Tests for key generation and key file persistence helpers."""

from __future__ import annotations

import os

import pytest
import rsa

from locksmith.core.keys import save_keypair


def test_generate_keypair_returns_public_then_private(keypair):
    pubkey, privkey = keypair

    assert isinstance(pubkey, rsa.PublicKey)
    assert isinstance(privkey, rsa.PrivateKey)
    assert pubkey.n == privkey.n
    assert pubkey.e == privkey.e


def test_save_keypair_sets_public_key_permissions(keypair, tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX-only permission assertion")

    pubkey, privkey = keypair
    priv_path, pub_path = save_keypair(pubkey, privkey, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()
    assert priv_path.stat().st_mode & 0o777 == 0o600
    assert pub_path.stat().st_mode & 0o777 == 0o644
