"""RSA key management and abstract signing interface.

The BaseSigner ABC allows a FileSigner (local PEM files) to be swapped for a
KMS-backed implementation (AWS KMS, HashiCorp Vault, etc.) without changing
any calling code.
"""

from __future__ import annotations

import asyncio
import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path

import rsa


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class BaseSigner(ABC):
    """Abstract signing interface. Implement this to add KMS / HSM support."""

    @abstractmethod
    async def sign(self, data: bytes) -> bytes:
        """Sign *data* and return the raw signature bytes."""

    @abstractmethod
    async def verify(self, data: bytes, signature: bytes) -> bool:
        """Return True if *signature* is valid for *data*, False otherwise."""


# ---------------------------------------------------------------------------
# File-based implementation
# ---------------------------------------------------------------------------


class FileSigner(BaseSigner):
    """RSA-4096 signer backed by local PKCS#1 PEM key files.

    Pass ``privkey=None`` to create a verify-only instance (e.g. on the
    client side where only the public key is distributed).
    """

    def __init__(
        self,
        privkey: rsa.PrivateKey | None,
        pubkey: rsa.PublicKey,
    ) -> None:
        self._privkey = privkey
        self._pubkey = pubkey

    # RSA operations are CPU-bound; run in the default thread-pool executor
    # so they do not block the asyncio event loop.

    async def sign(self, data: bytes) -> bytes:
        if self._privkey is None:
            raise ValueError(
                "This FileSigner instance has no private key (verify-only mode)."
            )
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: rsa.sign(data, self._privkey, "SHA-512")
        )

    async def verify(self, data: bytes, signature: bytes) -> bool:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None, lambda: rsa.verify(data, signature, self._pubkey)
            )
            return True
        except rsa.VerificationError:
            return False

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_files(
        cls,
        pubkey_path: Path | str,
        privkey_path: Path | str | None = None,
    ) -> FileSigner:
        """Load a FileSigner from PEM files on disk."""
        pubkey_path = Path(pubkey_path)
        privkey: rsa.PrivateKey | None = None

        if privkey_path is not None:
            with Path(privkey_path).open("rb") as f:
                privkey = rsa.PrivateKey.load_pkcs1(f.read())

        with pubkey_path.open("rb") as f:
            pubkey = rsa.PublicKey.load_pkcs1(f.read())

        return cls(privkey, pubkey)


# ---------------------------------------------------------------------------
# Key generation helpers
# ---------------------------------------------------------------------------


def generate_keypair(bits: int = 4096) -> tuple[rsa.PrivateKey, rsa.PublicKey]:
    """Generate a new RSA keypair. Blocking — run in a thread for async contexts."""
    return rsa.newkeys(bits)


def save_keypair(
    privkey: rsa.PrivateKey,
    pubkey: rsa.PublicKey,
    out_dir: Path | str,
) -> tuple[Path, Path]:
    """Write PKCS#1 PEM files and set restrictive permissions on POSIX systems."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    privkey_path = out_dir / "privkey.pem"
    pubkey_path = out_dir / "pubkey.pem"

    privkey_path.write_bytes(privkey.save_pkcs1())
    pubkey_path.write_bytes(pubkey.save_pkcs1())

    if os.name == "posix":
        os.chmod(privkey_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        os.chmod(pubkey_path, stat.S_IRUSR)  # 0400

    return privkey_path, pubkey_path
