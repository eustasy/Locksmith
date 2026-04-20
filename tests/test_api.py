"""API integration tests."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest
from httpx import ASGITransport, AsyncClient

from locksmith.core.license import License, TimePolicy, VersionPolicy
from locksmith.core.signer import sign_license


def _future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _past_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


@pytest.fixture(scope="module")
async def client(test_app):
    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as c:
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
        issued_at=datetime.now(timezone.utc),
        valid_from=datetime.now(timezone.utc),
        time_policy=TimePolicy.LIMITED,
        expires_at=datetime.now(timezone.utc) + timedelta(days=365),
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
