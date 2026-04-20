"""Tests for the License, Entitlement, and LicenseRequest data models."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from locksmith.core.license import (
    Entitlement,
    License,
    LicenseRequest,
    RestrictionMode,
    TimePolicy,
    VersionPolicy,
)


def _make_license(**overrides) -> License:
    defaults = dict(
        license_id="test-id-001",
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
        signature="fakesig==",
    )
    defaults.update(overrides)
    return License(**defaults)


# ---------------------------------------------------------------------------
# Basic roundtrip
# ---------------------------------------------------------------------------


def test_roundtrip_json():
    lic = _make_license(activation_limit=5)
    restored = License.from_json(lic.to_json())
    assert restored.license_id == lic.license_id
    assert restored.email == lic.email
    assert restored.activation_limit == 5
    assert restored.time_policy == TimePolicy.PERPETUAL
    assert restored.signature == lic.signature


def test_signable_payload_excludes_signature():
    lic = _make_license(signature="should_not_appear")
    payload = json.loads(lic.signable_payload())
    assert "signature" not in payload


def test_signable_payload_includes_entitlements():
    ent = Entitlement(app_id="com.example.app", editions=["pro"], seats=3)
    lic = _make_license(entitlements=[ent])
    payload = json.loads(lic.signable_payload())
    assert "entitlements" in payload
    assert payload["entitlements"][0]["app_id"] == "com.example.app"


def test_signable_payload_is_deterministic():
    lic = _make_license()
    assert lic.signable_payload() == lic.signable_payload()


# ---------------------------------------------------------------------------
# Time policy
# ---------------------------------------------------------------------------


def test_limited_roundtrip():
    exp = datetime.now(timezone.utc) + timedelta(days=365)
    lic = _make_license(time_policy=TimePolicy.LIMITED, expires_at=exp)
    restored = License.from_json(lic.to_json())
    assert restored.time_policy == TimePolicy.LIMITED
    assert restored.expires_at is not None


def test_perpetual_has_no_expires():
    lic = _make_license(time_policy=TimePolicy.PERPETUAL, expires_at=None)
    restored = License.from_json(lic.to_json())
    assert restored.expires_at is None


# ---------------------------------------------------------------------------
# Version policy
# ---------------------------------------------------------------------------


def test_maintenance_roundtrip():
    lic = _make_license(version_policy=VersionPolicy.MAINTENANCE, major_version=3)
    restored = License.from_json(lic.to_json())
    assert restored.version_policy == VersionPolicy.MAINTENANCE
    assert restored.major_version == 3


def test_specific_version_roundtrip():
    lic = _make_license(version_policy=VersionPolicy.SPECIFIC, locked_version="2.3.1")
    restored = License.from_json(lic.to_json())
    assert restored.version_policy == VersionPolicy.SPECIFIC
    assert restored.locked_version == "2.3.1"


# ---------------------------------------------------------------------------
# Edition / Platform normalisation
# ---------------------------------------------------------------------------


def test_editions_normalised_to_lowercase():
    lic = _make_license(editions=["Pro", "Enterprise"])
    assert lic.editions == ["pro", "enterprise"]


def test_platforms_normalised_to_lowercase():
    lic = _make_license(platforms=["Windows", "Windows_Server_2022"])
    assert lic.platforms == ["windows", "windows_server_2022"]


# ---------------------------------------------------------------------------
# Restriction
# ---------------------------------------------------------------------------


def test_activations_roundtrip():
    lic = _make_license(restriction=RestrictionMode.ACTIVATIONS, activation_limit=3)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.ACTIVATIONS
    assert restored.activation_limit == 3


def test_floating_roundtrip():
    lic = _make_license(restriction=RestrictionMode.FLOATING, concurrent_limit=10)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.FLOATING
    assert restored.concurrent_limit == 10


def test_users_roundtrip():
    lic = _make_license(restriction=RestrictionMode.USERS, user_limit=5)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.USERS
    assert restored.user_limit == 5


# ---------------------------------------------------------------------------
# Entitlements
# ---------------------------------------------------------------------------


def test_entitlement_roundtrip():
    ent = Entitlement(
        app_id="com.example.app",
        editions=["Professional", "Enterprise"],
        min_version="2.0.0",
        max_version="2.9.9",
        platforms=["Windows", "Linux"],
        seats=5,
    )
    restored = Entitlement.from_dict(ent.to_dict())
    assert restored.app_id == "com.example.app"
    assert restored.editions == ["professional", "enterprise"]
    assert restored.platforms == ["windows", "linux"]
    assert restored.seats == 5
    assert restored.min_version == "2.0.0"


def test_entitlement_none_fields_preserved():
    ent = Entitlement(app_id="com.example.app")
    d = ent.to_dict()
    assert d["editions"] is None
    assert d["platforms"] is None
    assert d["seats"] is None


def test_license_with_entitlements_roundtrip():
    ent = Entitlement(app_id="com.example.app", editions=["pro"], seats=3)
    lic = _make_license(entitlements=[ent])
    restored = License.from_json(lic.to_json())
    assert len(restored.entitlements) == 1
    assert restored.entitlements[0].app_id == "com.example.app"
    assert restored.entitlements[0].editions == ["pro"]
    assert restored.entitlements[0].seats == 3


def test_bundle_license_multiple_entitlements():
    ents = [
        Entitlement(app_id="com.example.app1", seats=2),
        Entitlement(app_id="com.example.app2", platforms=["windows"], seats=10),
    ]
    lic = _make_license(entitlements=ents)
    restored = License.from_json(lic.to_json())
    assert len(restored.entitlements) == 2
    assert restored.entitlements[1].platforms == ["windows"]


# ---------------------------------------------------------------------------
# License request
# ---------------------------------------------------------------------------


def test_license_request_roundtrip():
    req = LicenseRequest.new(
        "user@co.com",
        machine_id="abc123hash",
        app_version="2.0.0",
        app_id="com.example.app",
    )
    restored = LicenseRequest.from_json(req.to_json())
    assert restored.email == "user@co.com"
    assert restored.machine_id == "abc123hash"
    assert restored.app_id == "com.example.app"


# ---------------------------------------------------------------------------
# Time policy (additional)
# ---------------------------------------------------------------------------


def test_perpetual_roundtrip():
    lic = _make_license(time_policy=TimePolicy.PERPETUAL)
    assert License.from_json(lic.to_json()).time_policy == TimePolicy.PERPETUAL


# ---------------------------------------------------------------------------
# Version policy (additional)
# ---------------------------------------------------------------------------


def test_specific_roundtrip():
    lic = _make_license(version_policy=VersionPolicy.SPECIFIC, locked_version="2.5.1")
    restored = License.from_json(lic.to_json())
    assert restored.version_policy == VersionPolicy.SPECIFIC
    assert restored.locked_version == "2.5.1"


# ---------------------------------------------------------------------------
# Edition / Platform
# ---------------------------------------------------------------------------


def test_editions_normalised_lowercase():
    lic = _make_license(editions=["Pro", "Enterprise"])
    assert lic.editions == ["pro", "enterprise"]
    restored = License.from_json(lic.to_json())
    assert restored.editions == ["pro", "enterprise"]


def test_platforms_normalised_lowercase():
    lic = _make_license(platforms=["Windows", "macOS"])
    assert lic.platforms == ["windows", "macos"]


def test_null_editions_platforms_preserved():
    lic = _make_license()
    payload = json.loads(lic.signable_payload())
    assert payload["editions"] is None
    assert payload["platforms"] is None


# ---------------------------------------------------------------------------
# Restriction
# ---------------------------------------------------------------------------


def test_activations_restriction_roundtrip():
    lic = _make_license(restriction=RestrictionMode.ACTIVATIONS, activation_limit=5)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.ACTIVATIONS
    assert restored.activation_limit == 5


def test_users_restriction_roundtrip():
    lic = _make_license(restriction=RestrictionMode.USERS, user_limit=10)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.USERS
    assert restored.user_limit == 10


def test_floating_restriction_roundtrip():
    lic = _make_license(restriction=RestrictionMode.FLOATING, concurrent_limit=3)
    restored = License.from_json(lic.to_json())
    assert restored.restriction == RestrictionMode.FLOATING
    assert restored.concurrent_limit == 3


def test_no_restriction_roundtrip():
    lic = _make_license()
    restored = License.from_json(lic.to_json())
    assert restored.restriction is None


# ---------------------------------------------------------------------------
# License request (additional)
# ---------------------------------------------------------------------------


def test_license_request_no_machine_id():
    req = LicenseRequest.new("user@co.com", None, "1.0.0")
    restored = LicenseRequest.from_json(req.to_json())
    assert restored.machine_id is None
