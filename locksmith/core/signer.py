"""License signing and validation pipeline.

All validation flows through ``validate_license``, which always verifies the
cryptographic signature first before checking business rules.

Validation order:
  1. Cryptographic signature.
  2. ``valid_from`` / ``expires_at`` (temporal validity).
  3. Version policy (any / maintenance / specific).
  4. Entitlement matching — if entitlements are present, the caller must supply
     ``app_id`` and a matching entitlement must be found.
  5. Effective edition check — uses the matched entitlement's editions list,
     falling back to the license-level ``editions`` if none.
  6. Effective platform check — same fallback logic as editions.
  7. Entitlement version-range check (``min_version`` / ``max_version``),
     independent of the license-level version policy.

``machine_id`` and ``user_principal`` are threaded through to the activation
layer but are not validated cryptographically here — restriction enforcement
against database counts happens in ``routes/activate.py``.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

from .keys import BaseSigner
from .license import Entitlement, License, VersionPolicy


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class LicenseError(Exception):
    """Base class for all license validation failures."""


class LicenseMissingSignatureError(LicenseError):
    """License has no signature field."""


class LicenseVerificationError(LicenseError):
    """Cryptographic signature does not match the license payload."""


class LicenseNotYetValidError(LicenseError):
    """``valid_from`` is in the future."""


class LicenseExpiredError(LicenseError):
    """License has passed its ``expires_at`` date."""


class LicenseVersionError(LicenseError):
    """App version is outside the range permitted by the license."""


class LicenseEditionError(LicenseError):
    """Application edition is not permitted by the license or matched entitlement."""


class LicenseOSError(LicenseError):
    """Host operating system is not permitted by the license or matched entitlement."""


class LicenseAppError(LicenseError):
    """No entitlement found for the requested application."""


# ---------------------------------------------------------------------------
# Version parsing helper
# ---------------------------------------------------------------------------


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable tuple of ints.

    Non-numeric segments are ignored. ``"2.1.0"`` → ``(2, 1, 0)``.
    """
    parts = []
    for segment in v.split("."):
        if segment.isdigit():
            parts.append(int(segment))
    return tuple(parts) if parts else (0,)


# ---------------------------------------------------------------------------
# Sign / verify helpers
# ---------------------------------------------------------------------------


async def sign_license(license: License, signer: BaseSigner) -> License:
    """Sign the license payload and attach the base64url signature in-place."""
    payload = license.signable_payload()
    raw_sig = await signer.sign(payload)
    license.signature = base64.urlsafe_b64encode(raw_sig).decode("ascii")
    return license


async def verify_license_signature(license: License, signer: BaseSigner) -> None:
    """Raise ``LicenseVerificationError`` if the signature is absent or invalid."""
    if not license.signature:
        raise LicenseMissingSignatureError("License has no signature.")

    payload = license.signable_payload()
    raw_sig = base64.urlsafe_b64decode(license.signature.encode("ascii"))
    ok = await signer.verify(payload, raw_sig)
    if not ok:
        raise LicenseVerificationError("License signature verification failed.")


# ---------------------------------------------------------------------------
# Full validation pipeline
# ---------------------------------------------------------------------------


async def validate_license(
    license: License,
    signer: BaseSigner,
    *,
    machine_id: Optional[str] = None,
    user_principal: Optional[str] = None,
    app_id: Optional[str] = None,
    app_version: Optional[str] = None,
    edition: Optional[str] = None,
    platform: Optional[str] = None,
) -> Optional[Entitlement]:
    """Validate a license end-to-end. Raises a ``LicenseError`` subclass on failure.

    Returns the matched ``Entitlement`` if the license has entitlements and one
    was found, or ``None`` if the license is app-unrestricted.
    """
    # 1. Signature — must always be first
    await verify_license_signature(license, signer)

    now = datetime.now(timezone.utc)

    # 2. Temporal validity
    valid_from = license.valid_from
    if valid_from.tzinfo is None:
        valid_from = valid_from.replace(tzinfo=timezone.utc)
    if now < valid_from:
        raise LicenseNotYetValidError(
            f"License is not valid until {license.valid_from.isoformat()}."
        )

    if license.expires_at is not None:
        expires_at = license.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            raise LicenseExpiredError(
                f"License expired on {license.expires_at.isoformat()}."
            )

    # 3. Version policy
    if license.version_policy == VersionPolicy.MAINTENANCE:
        if app_version is None:
            raise LicenseVersionError(
                "app_version is required for maintenance license validation."
            )
        app_major = _parse_version(app_version)[0]
        if license.major_version != app_major:
            raise LicenseVersionError(
                f"License covers major version {license.major_version}, "
                f"but the application is version {app_version}."
            )
    elif license.version_policy == VersionPolicy.SPECIFIC:
        if app_version is None:
            raise LicenseVersionError(
                "app_version is required for specific-version license validation."
            )
        if license.locked_version != app_version:
            raise LicenseVersionError(
                f"License is locked to version {license.locked_version}, "
                f"but the application is version {app_version}."
            )

    # 4. Entitlement matching
    matched: Optional[Entitlement] = None

    if license.entitlements:
        if app_id is None:
            raise LicenseAppError(
                "This license restricts access by application. "
                "Provide app_id to validate."
            )

        for ent in license.entitlements:
            if ent.app_id == app_id:
                matched = ent
                break

        if matched is None:
            raise LicenseAppError(
                f"This license does not cover application '{app_id}'."
            )

    # 5. Effective edition check
    # Entitlement editions override license-level; None on either = no restriction.
    eff_editions = (
        matched.editions
        if (matched is not None and matched.editions is not None)
        else license.editions
    )
    if eff_editions is not None:
        if edition is None or edition.lower() not in eff_editions:
            raise LicenseEditionError(
                f"Edition '{edition}' is not permitted. "
                f"Allowed editions: {', '.join(eff_editions)}."
            )

    # 6. Effective platform check (same fallback logic)
    eff_platforms = (
        matched.platforms
        if (matched is not None and matched.platforms is not None)
        else license.platforms
    )
    if eff_platforms is not None:
        if platform is None or platform.lower() not in eff_platforms:
            raise LicenseOSError(
                f"Platform '{platform}' is not permitted. "
                f"Allowed platforms: {', '.join(eff_platforms)}."
            )

    # 7. Entitlement version range (per-app, complements the license-level version policy)
    if matched is not None:
        if app_version is not None:
            parsed = _parse_version(app_version)
            if matched.min_version is not None:
                if parsed < _parse_version(matched.min_version):
                    raise LicenseVersionError(
                        f"App version {app_version} is below the minimum "
                        f"required version {matched.min_version}."
                    )
            if matched.max_version is not None:
                if parsed > _parse_version(matched.max_version):
                    raise LicenseVersionError(
                        f"App version {app_version} exceeds the maximum "
                        f"covered version {matched.max_version}."
                    )
        elif matched.min_version is not None or matched.max_version is not None:
            raise LicenseVersionError(
                "app_version is required to validate a version-restricted entitlement."
            )

    return matched
