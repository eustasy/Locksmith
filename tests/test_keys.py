"""Tests for key generation and key file persistence helpers."""

from __future__ import annotations

import os

import pytest
import rsa

from locksmith.core.keys import save_keypair


def test_keypair_fixture_has_valid_rsa_keys(keypair):
    pubkey, privkey = keypair

    assert isinstance(pubkey, rsa.PublicKey)
    assert isinstance(privkey, rsa.PrivateKey)
    assert pubkey.n == privkey.n
    assert pubkey.e == privkey.e
    assert privkey.d > 0
    assert privkey.p > 0
    assert privkey.q > 0
    assert privkey.p * privkey.q == privkey.n
    phi_n = (privkey.p - 1) * (privkey.q - 1)
    assert (privkey.d * privkey.e) % phi_n == 1


def test_save_keypair_sets_private_and_public_key_permissions(keypair, tmp_path):
    pubkey, privkey = keypair
    priv_path, pub_path = save_keypair(pubkey, privkey, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()

    if os.name == "posix":
        assert priv_path.stat().st_mode & 0o777 == 0o600
        assert pub_path.stat().st_mode & 0o777 == 0o644

    loaded_privkey = rsa.PrivateKey.load_pkcs1(priv_path.read_bytes())
    loaded_pubkey = rsa.PublicKey.load_pkcs1(pub_path.read_bytes())
    assert loaded_privkey == privkey
    assert loaded_pubkey == pubkey
