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


@pytest.mark.skipif(
    os.name != "posix",
    reason="POSIX file mode bits are not portable to Windows",
)
def test_save_keypair_sets_private_and_public_key_permissions(keypair, tmp_path):
    pubkey, privkey = keypair
    priv_path, pub_path = save_keypair(pubkey, privkey, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()

    assert priv_path.stat().st_mode & 0o777 == 0o600
    assert pub_path.stat().st_mode & 0o777 == 0o644

    loaded_privkey = rsa.PrivateKey.load_pkcs1(priv_path.read_bytes())
    loaded_pubkey = rsa.PublicKey.load_pkcs1(pub_path.read_bytes())
    assert loaded_privkey == privkey
    assert loaded_pubkey == pubkey


def test_save_keypair_raises_when_target_path_is_not_a_directory(keypair, tmp_path):
    pubkey, privkey = keypair
    not_a_directory = tmp_path / "not_a_directory"
    not_a_directory.write_text("this is a file, not a directory")

    with pytest.raises(OSError):
        save_keypair(pubkey, privkey, not_a_directory)


@pytest.mark.skipif(
    os.name == "posix",
    reason="On non-POSIX, verify save_keypair succeeds and keys roundtrip without asserting POSIX mode bits",
)
def test_save_keypair_succeeds_without_permission_bit_assertions_on_non_posix(
    keypair, tmp_path
):
    pubkey, privkey = keypair
    priv_path, pub_path = save_keypair(pubkey, privkey, tmp_path)

    assert priv_path.exists()
    assert pub_path.exists()

    loaded_privkey = rsa.PrivateKey.load_pkcs1(priv_path.read_bytes())
    loaded_pubkey = rsa.PublicKey.load_pkcs1(pub_path.read_bytes())

    assert loaded_privkey == privkey
    assert loaded_pubkey == pubkey


def test_load_pkcs1_raises_for_corrupted_key_files(tmp_path):
    priv_path = tmp_path / "id_rsa"
    pub_path = tmp_path / "id_rsa.pub"

    priv_path.write_bytes(b"not-a-valid-private-key")
    pub_path.write_bytes(b"not-a-valid-public-key")

    with pytest.raises((ValueError, IndexError, TypeError)):
        rsa.PrivateKey.load_pkcs1(priv_path.read_bytes())

    with pytest.raises((ValueError, IndexError, TypeError)):
        rsa.PublicKey.load_pkcs1(pub_path.read_bytes())
