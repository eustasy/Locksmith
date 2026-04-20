"""Tests for the signing and validation pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from locksmith.core.license import Entitlement, License, TimePolicy, VersionPolicy
from locksmith.core.signer import (
    LicenseAppError,
    LicenseEditionError,
    LicenseExpiredError,
    LicenseMissingSignatureError,
    LicenseNotYetValidError,
    LicenseOSError,
    LicenseVerificationError,
    LicenseVersionError,
    sign_license,
    validate_license,
)


def _make_license(**overrides) -> License:
    defaults = dict(
        license_id="signer-test-001",
        email="test@example.com",
        issued_at=datetime.now(timezone.utc),
        valid_from=datetime.now(timezone.utc),
        time_policy=TimePolicy.PERPETUAL,
        expires_at=None,
        version_policy=VersionPolicy.ANY,
        major_version=None,
        locked_version=None,
        editions=None,
        platforms=None,
        restriction=None,
        activation_limit=None,
        user_limit=None,
        concurrent_limit=None,
        entitlements=None,
    )
    defaults.update(overrides)
    return License(**defaults)


# ---------------------------------------------------------------------------
# Core sign / verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_and_verify_roundtrip(file_signer):
    lic = _make_license()
    await sign_license(lic, file_signer)
    assert lic.signature is not None
    await validate_license(lic, file_signer)  # should not raise


@pytest.mark.asyncio
async def test_missing_signature_raises(file_signer):
    lic = _make_license()
    with pytest.raises(LicenseMissingSignatureError):
        await validate_license(lic, file_signer)


@pytest.mark.asyncio
async def test_tampered_email_raises(file_signer):
    lic = _make_license()
    await sign_license(lic, file_signer)
    lic.email = "attacker@evil.com"
    with pytest.raises(LicenseVerificationError):
        await validate_license(lic, file_signer)


@pytest.mark.asyncio
async def test_tampered_activation_limit_raises(file_signer):
    lic = _make_license(activation_limit=1)
    await sign_license(lic, file_signer)
    lic.activation_limit = 9999
    with pytest.raises(LicenseVerificationError):
        await validate_license(lic, file_signer)


@pytest.mark.asyncio
async def test_tampered_entitlement_raises(file_signer):
    """Modifying an entitlement after signing must invalidate the signature."""
    ent = Entitlement(app_id="com.example.app", seats=2)
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    lic.entitlements[0].seats = 9999
    with pytest.raises(LicenseVerificationError):
        await validate_license(
            lic, file_signer, app_id="com.example.app", app_version="1.0.0"
        )


# ---------------------------------------------------------------------------
# Temporal validity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_license_raises(file_signer):
    lic = _make_license(
        time_policy=TimePolicy.LIMITED,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseExpiredError):
        await validate_license(lic, file_signer)


@pytest.mark.asyncio
async def test_not_yet_valid_raises(file_signer):
    lic = _make_license(valid_from=datetime.now(timezone.utc) + timedelta(days=1))
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseNotYetValidError):
        await validate_license(lic, file_signer)


# ---------------------------------------------------------------------------
# Version policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_maintenance_correct_version(file_signer):
    lic = _make_license(version_policy=VersionPolicy.MAINTENANCE, major_version=2)
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, app_version="2.5.0")


@pytest.mark.asyncio
async def test_maintenance_wrong_version_raises(file_signer):
    lic = _make_license(version_policy=VersionPolicy.MAINTENANCE, major_version=2)
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseVersionError):
        await validate_license(lic, file_signer, app_version="3.0.0")


@pytest.mark.asyncio
async def test_specific_version_correct(file_signer):
    lic = _make_license(version_policy=VersionPolicy.SPECIFIC, locked_version="2.3.1")
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, app_version="2.3.1")


@pytest.mark.asyncio
async def test_specific_version_wrong_raises(file_signer):
    lic = _make_license(version_policy=VersionPolicy.SPECIFIC, locked_version="2.3.1")
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseVersionError):
        await validate_license(lic, file_signer, app_version="2.3.2")


# ---------------------------------------------------------------------------
# Edition (license-level)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_license_edition_allowed(file_signer):
    lic = _make_license(editions=["pro", "enterprise"])
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, edition="Pro")  # case-insensitive


@pytest.mark.asyncio
async def test_license_edition_denied_raises(file_signer):
    lic = _make_license(editions=["pro"])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseEditionError):
        await validate_license(lic, file_signer, edition="enterprise")


# ---------------------------------------------------------------------------
# Platform (license-level)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_license_platform_allowed(file_signer):
    lic = _make_license(platforms=["windows", "linux"])
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, platform="Linux")  # case-insensitive


@pytest.mark.asyncio
async def test_license_platform_denied_raises(file_signer):
    lic = _make_license(platforms=["windows"])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseOSError):
        await validate_license(lic, file_signer, platform="linux")


@pytest.mark.asyncio
async def test_specific_os_platform(file_signer):
    lic = _make_license(platforms=["windows_server_2022"])
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, platform="windows_server_2022")
    with pytest.raises(LicenseOSError):
        await validate_license(lic, file_signer, platform="windows")


# ---------------------------------------------------------------------------
# Entitlements — app_id matching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entitlement_app_id_match(file_signer):
    ent = Entitlement(app_id="com.example.app")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    matched = await validate_license(lic, file_signer, app_id="com.example.app")
    assert matched is not None
    assert matched.app_id == "com.example.app"


@pytest.mark.asyncio
async def test_entitlement_wrong_app_raises(file_signer):
    ent = Entitlement(app_id="com.example.app")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseAppError):
        await validate_license(lic, file_signer, app_id="com.example.other")


@pytest.mark.asyncio
async def test_entitlement_no_app_id_raises_when_required(file_signer):
    ent = Entitlement(app_id="com.example.app")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseAppError):
        await validate_license(lic, file_signer)  # no app_id


@pytest.mark.asyncio
async def test_no_entitlements_no_app_id_ok(file_signer):
    lic = _make_license()
    await sign_license(lic, file_signer)
    matched = await validate_license(lic, file_signer)
    assert matched is None


# ---------------------------------------------------------------------------
# Entitlements — edition override
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entitlement_edition_override(file_signer):
    """Entitlement edition list overrides license-level editions."""
    ent = Entitlement(app_id="com.app", editions=["pro"])
    lic = _make_license(editions=["enterprise"], entitlements=[ent])
    await sign_license(lic, file_signer)
    # edition "pro" denied by license-level but allowed by entitlement
    await validate_license(lic, file_signer, app_id="com.app", edition="pro")


@pytest.mark.asyncio
async def test_entitlement_edition_denied_raises(file_signer):
    ent = Entitlement(app_id="com.app", editions=["professional"])
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseEditionError):
        await validate_license(lic, file_signer, app_id="com.app", edition="enterprise")


# ---------------------------------------------------------------------------
# Entitlements — version range
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entitlement_version_within_range(file_signer):
    ent = Entitlement(app_id="com.app", min_version="2.0.0", max_version="2.9.9")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, app_id="com.app", app_version="2.5.0")


@pytest.mark.asyncio
async def test_entitlement_version_below_min_raises(file_signer):
    ent = Entitlement(app_id="com.app", min_version="2.0.0")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseVersionError):
        await validate_license(lic, file_signer, app_id="com.app", app_version="1.9.9")


@pytest.mark.asyncio
async def test_entitlement_version_above_max_raises(file_signer):
    ent = Entitlement(app_id="com.app", max_version="2.9.9")
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseVersionError):
        await validate_license(lic, file_signer, app_id="com.app", app_version="3.0.0")


# ---------------------------------------------------------------------------
# Entitlements — platform override
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entitlement_platform_override(file_signer):
    ent = Entitlement(app_id="com.app", platforms=["linux"])
    lic = _make_license(platforms=["windows"], entitlements=[ent])
    await sign_license(lic, file_signer)
    await validate_license(lic, file_signer, app_id="com.app", platform="linux")


@pytest.mark.asyncio
async def test_entitlement_platform_denied_raises(file_signer):
    ent = Entitlement(app_id="com.app", platforms=["windows"])
    lic = _make_license(entitlements=[ent])
    await sign_license(lic, file_signer)
    with pytest.raises(LicenseOSError):
        await validate_license(lic, file_signer, app_id="com.app", platform="linux")


# ---------------------------------------------------------------------------
# Bundle license
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bundle_second_app_matches(file_signer):
    ents = [
        Entitlement(app_id="com.example.app1", seats=2),
        Entitlement(app_id="com.example.app2", platforms=["macos"], seats=5),
    ]
    lic = _make_license(entitlements=ents)
    await sign_license(lic, file_signer)
    matched = await validate_license(
        lic, file_signer, app_id="com.example.app2", platform="macos"
    )
    assert matched is not None
    assert matched.seats == 5


# ---------------------------------------------------------------------------
# Verify-only signer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_only_signer_cannot_sign(verify_only_signer):
    lic = _make_license()
    with pytest.raises(ValueError, match="no private key"):
        await sign_license(lic, verify_only_signer)


from datetime import datetime, timedelta, timezone
