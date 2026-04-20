"""Admin routes — issue, inspect, and revoke licenses.

All routes require a valid ``Authorization: Bearer <LOCKSMITH_ADMIN_API_KEY>``
header.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from locksmith.api.auth import require_admin
from locksmith.api.schemas import IssueRequest, LicenseMetadata
from locksmith.core.license import (
    Entitlement,
    License,
    TimePolicy,
    VersionPolicy,
    RestrictionMode,
)
from locksmith.core.signer import sign_license
from locksmith.core.store import (
    count_active_activations,
    get_license,
    get_session,
    revoke_license,
    save_license,
)

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("", status_code=status.HTTP_201_CREATED, response_class=PlainTextResponse)
async def issue_license(body: IssueRequest, request: Request) -> PlainTextResponse:
    """Issue a new signed license and return the raw ``.lic`` JSON."""
    lic = License(
        license_id=str(uuid.uuid4()),
        email=body.email,
        issued_at=datetime.now(timezone.utc),
        valid_from=body.valid_from,
        time_policy=body.time_policy,
        expires_at=body.expires_at,
        version_policy=body.version_policy,
        major_version=body.major_version,
        locked_version=body.locked_version,
        editions=body.editions,
        platforms=body.platforms,
        restriction=body.restriction,
        activation_limit=body.activation_limit,
        user_limit=body.user_limit,
        concurrent_limit=body.concurrent_limit,
        entitlements=[
            Entitlement(
                app_id=e.app_id,
                editions=e.editions,
                min_version=e.min_version,
                max_version=e.max_version,
                platforms=e.platforms,
                seats=e.seats,
            )
            for e in body.entitlements
        ],
    )

    await sign_license(lic, request.app.state.signer)

    async with get_session() as session:
        await save_license(session, lic)

    return PlainTextResponse(lic.to_json(), status_code=status.HTTP_201_CREATED)


@router.get("/{license_id}", response_model=LicenseMetadata)
async def get_license_detail(license_id: str) -> LicenseMetadata:
    """Return metadata for a single license."""
    async with get_session() as session:
        row = await get_license(session, license_id)
        if row is None:
            raise HTTPException(status_code=404, detail="License not found.")
        active = await count_active_activations(session, license_id)

    return LicenseMetadata(
        license_id=row.license_id,
        email=row.email,
        issued_at=row.issued_at,
        valid_from=row.valid_from,
        time_policy=row.time_policy,
        expires_at=row.expires_at,
        version_policy=row.version_policy,
        major_version=row.major_version,
        locked_version=row.locked_version,
        editions=row.editions_json,
        platforms=row.platforms_json,
        restriction=row.restriction,
        activation_limit=row.activation_limit,
        user_limit=row.user_limit,
        concurrent_limit=row.concurrent_limit,
        entitlements=row.entitlements_json or [],
        revoked=row.revoked,
        active_count=active,
    )


@router.delete("/{license_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_license_endpoint(license_id: str) -> None:
    """Revoke a license. Active activations can no longer call ``/activate``."""
    async with get_session() as session:
        ok = await revoke_license(session, license_id)
    if not ok:
        raise HTTPException(status_code=404, detail="License not found.")


import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse

from locksmith.api.auth import require_admin
from locksmith.api.schemas import IssueRequest, LicenseMetadata
from locksmith.core.license import Entitlement, License
from locksmith.core.signer import sign_license
from locksmith.core.store import (
    count_active_activations,
    get_license,
    get_session,
    revoke_license,
    save_license,
)

router = APIRouter(dependencies=[Depends(require_admin)])


@router.post("", status_code=status.HTTP_201_CREATED, response_class=PlainTextResponse)
async def issue_license(body: IssueRequest, request: Request) -> PlainTextResponse:
    """Issue a new signed license and return the raw ``.lic`` JSON."""
    lic = License(
        license_id=str(uuid.uuid4()),
        type=body.type,
        email=body.email,
        issued_at=datetime.now(timezone.utc),
        valid_from=body.valid_from,
        expires_at=body.expires_at,
        major_version=body.major_version,
        machine_id=body.machine_id,
        user_principal=body.user_principal,
        seats=body.seats,
        entitlements=[
            Entitlement(
                app_id=e.app_id,
                editions=e.editions,
                min_version=e.min_version,
                max_version=e.max_version,
                platforms=e.platforms,
                seats=e.seats,
            )
            for e in body.entitlements
        ],
    )

    await sign_license(lic, request.app.state.signer)

    async with get_session() as session:
        await save_license(session, lic)

    return PlainTextResponse(lic.to_json(), status_code=status.HTTP_201_CREATED)


@router.get("/{license_id}", response_model=LicenseMetadata)
async def get_license_detail(license_id: str) -> LicenseMetadata:
    """Return metadata for a single license."""
    async with get_session() as session:
        row = await get_license(session, license_id)
        if row is None:
            raise HTTPException(status_code=404, detail="License not found.")
        active = await count_active_activations(session, license_id)

    return LicenseMetadata(
        license_id=row.license_id,
        type=row.type,
        email=row.email,
        issued_at=row.issued_at,
        valid_from=row.valid_from,
        expires_at=row.expires_at,
        major_version=row.major_version,
        machine_id=row.machine_id,
        user_principal=row.user_principal,
        seats=row.seats,
        entitlements=row.entitlements_json or [],
        revoked=row.revoked,
        active_activations=active,
    )


@router.delete("/{license_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_license_endpoint(license_id: str) -> None:
    """Revoke a license. Active activations can no longer call ``/activate``."""
    async with get_session() as session:
        ok = await revoke_license(session, license_id)
    if not ok:
        raise HTTPException(status_code=404, detail="License not found.")
