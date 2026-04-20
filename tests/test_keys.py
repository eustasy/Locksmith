"""Tests for key generation and key file persistence helpers."""

from __future__ import annotations

import os

import pytest
import rsa

from locksmith.core.keys import generate_keypair, save_keypair


def test_generate_keypair_returns_private_then_public():
    privkey, pubkey = generate_keypair(512)

    assert isinstance(privkey, rsa.PrivateKey)
    assert isinstance(pubkey, rsa.PublicKey)
    assert privkey.n == pubkey.n
    assert privkey.e == pubkey.e


def test_save_keypair_sets_public_key_permissions(keypair, tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX-only permission assertion")

    privkey, pubkey = keypair
    priv_path, pub_path = save_keypair(privkey, pubkey, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()
    assert priv_path.stat().st_mode & 0o777 == 0o600
    assert pub_path.stat().st_mode & 0o777 == 0o644
