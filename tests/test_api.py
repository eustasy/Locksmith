"""API integration tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from httpx import ASGITransport, AsyncClient

from locksmith.core.license import License, TimePolicy, VersionPolicy
from locksmith.core.signer import sign_license


def _future_iso() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def _past_iso() -> str:
    return (datetime.now(UTC) - timedelta(days=1)).isoformat()


@pytest.fixture(scope="module")
async def client(test_app):
    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# Admin — issue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_issue_requires_auth(client):
    resp = await client.post("/licenses", json={})
    assert resp.status_code in (401, 403)  # no bearer token (starlette 1.x returns 401)


@pytest.mark.asyncio
async def test_issue_bad_key(client):
    from locksmith.core.config import settings

    original = settings.admin_api_key
    settings.admin_api_key = "somekey"
    try:
        resp = await client.post(
            "/licenses",
            json={},
            headers={"Authorization": "Bearer wrongkey"},
        )
        assert resp.status_code == 401
    finally:
        settings.admin_api_key = original


@pytest.mark.asyncio
async def test_issue_and_get(client, test_app):
    from locksmith.core.config import settings

    original = settings.admin_api_key
    settings.admin_api_key = "testkey123"

    payload = {
        "email": "user@example.com",
        "valid_from": _future_iso(),
        "time_policy": "perpetual",
        "version_policy": "any",
        "restriction": "activations",
        "activation_limit": 2,
    }
    resp = await client.post(
        "/licenses",
        json=payload,
        headers={"Authorization": "Bearer testkey123"},
    )
    assert resp.status_code == 201
    lic = json.loads(resp.text)
    assert lic["email"] == "user@example.com"
    assert lic["activation_limit"] == 2
    assert lic["signature"] is not None

    license_id = lic["license_id"]

    # GET metadata
    resp2 = await client.get(
        f"/licenses/{license_id}",
        headers={"Authorization": "Bearer testkey123"},
    )
    assert resp2.status_code == 200
    meta = resp2.json()
    assert meta["license_id"] == license_id
    assert meta["active_count"] == 0

    settings.admin_api_key = original


# ---------------------------------------------------------------------------
# Offline validate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_valid_license(client, file_signer):
    lic = License(
        license_id=str(uuid.uuid4()),
        email="offline@example.com",
        issued_at=datetime.now(UTC),
        valid_from=datetime.now(UTC),
        time_policy=TimePolicy.LIMITED,
        expires_at=datetime.now(UTC) + timedelta(days=365),
        version_policy=VersionPolicy.ANY,
    )
    await sign_license(lic, file_signer)

    lic_bytes = lic.to_json().encode("utf-8")
    resp = await client.post(
        "/validate",
        files={"file": ("license.lic", BytesIO(lic_bytes), "application/json")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["email"] == "offline@example.com"


@pytest.mark.asyncio
async def test_validate_wrong_extension_rejected(client):
    resp = await client.post(
        "/validate",
        files={"file": ("license.txt", BytesIO(b"{}"), "text/plain")},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Online activation
# ---------------------------------------------------------------------------


async def _issue_license(client, **overrides) -> dict:
    """Issue a currently-valid license via the admin API; return the parsed .lic JSON."""
    from locksmith.core.config import settings

    payload = {
        "email": "activate@example.com",
        "valid_from": _past_iso(),
        "time_policy": "perpetual",
        "version_policy": "any",
    }
    payload.update(overrides)

    original = settings.admin_api_key
    settings.admin_api_key = "testkey123"
    try:
        resp = await client.post(
            "/licenses",
            json=payload,
            headers={"Authorization": "Bearer testkey123"},
        )
    finally:
        settings.admin_api_key = original
    assert resp.status_code == 201, resp.text
    return json.loads(resp.text)


async def _activate(client, license_id: str, **fields):
    body = {"license_id": license_id, "app_id": "com.example.app", "app_version": "1.0.0"}
    body.update(fields)
    return await client.post("/activate", json=body)


@pytest.mark.asyncio
async def test_activate_reactivation_is_idempotent(client):
    lic = await _issue_license(client, restriction="activations", activation_limit=2)
    lid = lic["license_id"]

    r1 = await _activate(client, lid, machine_id="machine-A")
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["status"] == "activated"
    assert body1["app_id"] == "*"  # unrestricted (no entitlements) → wildcard app
    assert body1["limit"] == 2
    assert body1["active_count"] == 1

    # Re-activating the same machine must not consume a second seat.
    r2 = await _activate(client, lid, machine_id="machine-A")
    assert r2.status_code == 200
    assert r2.json()["active_count"] == 1


@pytest.mark.asyncio
async def test_activate_enforces_activation_limit(client):
    lid = (await _issue_license(client, restriction="activations", activation_limit=2))["license_id"]

    assert (await _activate(client, lid, machine_id="m1")).status_code == 200
    assert (await _activate(client, lid, machine_id="m2")).status_code == 200

    r3 = await _activate(client, lid, machine_id="m3")
    assert r3.status_code == 403
    assert "Limit of 2 reached" in r3.json()["detail"]


@pytest.mark.asyncio
async def test_activate_missing_machine_id_returns_422(client):
    lid = (await _issue_license(client, restriction="activations", activation_limit=1))["license_id"]
    r = await _activate(client, lid)  # no machine_id supplied
    assert r.status_code == 422
    assert "machine_id is required" in r.json()["detail"]


@pytest.mark.asyncio
async def test_activate_users_mode(client):
    lid = (await _issue_license(client, restriction="users", user_limit=1))["license_id"]

    # users restriction without user_principal → 422 (machine_id is ignored here)
    r = await _activate(client, lid, machine_id="ignored")
    assert r.status_code == 422
    assert "user_principal is required" in r.json()["detail"]

    # with user_principal → succeeds, seat consumed against user_limit
    r2 = await _activate(client, lid, user_principal="alice@example.com")
    assert r2.status_code == 200
    body = r2.json()
    assert body["limit"] == 1
    assert body["active_count"] == 1


@pytest.mark.asyncio
async def test_activate_unknown_license_returns_404(client):
    r = await _activate(client, "does-not-exist", machine_id="m1")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_activate_revoked_license_returns_403(client):
    from locksmith.core.config import settings

    lid = (await _issue_license(client, restriction="activations", activation_limit=1))["license_id"]

    original = settings.admin_api_key
    settings.admin_api_key = "testkey123"
    try:
        rev = await client.delete(f"/licenses/{lid}", headers={"Authorization": "Bearer testkey123"})
        assert rev.status_code == 204
    finally:
        settings.admin_api_key = original

    r = await _activate(client, lid, machine_id="m1")
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_floating_activate_then_deactivate_releases_seat(client):
    lid = (await _issue_license(client, restriction="floating", concurrent_limit=1))["license_id"]

    r1 = await _activate(client, lid, machine_id="sess-1")
    assert r1.status_code == 200
    assert r1.json()["active_count"] == 1

    # A second concurrent session exceeds concurrent_limit=1.
    assert (await _activate(client, lid, machine_id="sess-2")).status_code == 403

    # Releasing the first seat frees capacity for the next session.
    deact = await client.post(
        "/deactivate",
        json={"license_id": lid, "app_id": "*", "machine_id": "sess-1"},
    )
    assert deact.status_code == 204

    r3 = await _activate(client, lid, machine_id="sess-2")
    assert r3.status_code == 200
