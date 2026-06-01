"""Online activation and deactivation endpoints.

``POST /activate`` — clients call this on every fresh install (or periodically)
to validate their license against the server. The server checks:
  - License exists and is not revoked
  - Cryptographic signature is valid
  - License has not expired and is within its version/edition/platform constraints
  - The applicable limit (activation / user / concurrent) is not exceeded

Re-activating the same (license, app, identity) tuple always succeeds if the
license is otherwise valid.

``POST /deactivate`` — clients call this to release a seat (required for
floating licenses; optional for activations/users).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from locksmith.api.schemas import ActivateRequest, ActivateResponse, DeactivateRequest
from locksmith.core.keys import BaseSigner
from locksmith.core.license import Entitlement, License, RestrictionMode
from locksmith.core.signer import LicenseError, validate_license
from locksmith.core.store import (
    DBActivation,
    DBLicense,
    count_active_activations,
    get_license,
    get_session,
    record_activation,
    revoke_activation,
)

router = APIRouter()


def _row_to_license_dict(row) -> dict:
    return {
        "license_id": row.license_id,
        "email": row.email,
        "issued_at": row.issued_at.isoformat(),
        "valid_from": row.valid_from.isoformat(),
        "time_policy": row.time_policy,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "version_policy": row.version_policy,
        "major_version": row.major_version,
        "locked_version": row.locked_version,
        "editions": row.editions_json,
        "platforms": row.platforms_json,
        "restriction": row.restriction,
        "activation_limit": row.activation_limit,
        "user_limit": row.user_limit,
        "concurrent_limit": row.concurrent_limit,
        "entitlements": row.entitlements_json or [],
        "signature": row.signature,
    }


def _effective_limit(matched: Entitlement | None, fallback: int | None) -> int | None:
    """Per-app seat override when the matched entitlement sets one, else the license-level limit."""
    if matched is not None and matched.seats is not None:
        return matched.seats
    return fallback


async def _load_validated_license(
    session: AsyncSession,
    body: ActivateRequest,
    signer: BaseSigner,
) -> tuple[DBLicense, Entitlement | None]:
    """Load the license row, reject missing/revoked, and run full validation.

    Returns ``(row, matched_entitlement)``. Raises ``HTTPException`` 404 (not found),
    403 (revoked, or any ``LicenseError`` from validation).
    """
    row = await get_license(session, body.license_id)
    if row is None:
        raise HTTPException(status_code=404, detail="License not found.")
    if row.revoked:
        raise HTTPException(status_code=403, detail="License has been revoked.")

    lic = License.from_dict(_row_to_license_dict(row))
    try:
        matched = await validate_license(
            lic,
            signer,
            machine_id=body.machine_id,
            user_principal=body.user_principal,
            app_id=body.app_id,
            app_version=body.app_version,
            edition=body.edition,
            platform=body.platform,
        )
    except LicenseError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return row, matched


def _resolve_identity_and_limit(
    body: ActivateRequest,
    row: DBLicense,
    matched: Entitlement | None,
) -> tuple[str, int | None]:
    """Pick the activation identity and applicable seat limit for the restriction mode.

    Raises ``HTTPException`` 422 when the identity field the mode requires is absent.
    """
    if row.restriction == RestrictionMode.USERS.value:
        if not body.user_principal:
            raise HTTPException(status_code=422, detail="user_principal is required for user-restricted licenses.")
        return body.user_principal, _effective_limit(matched, row.user_limit)

    if not body.machine_id:
        raise HTTPException(status_code=422, detail="machine_id is required for this license.")
    if row.restriction == RestrictionMode.FLOATING.value:
        return body.machine_id, _effective_limit(matched, row.concurrent_limit)
    # "activations" or None — unrestricted licenses still count seats if a limit is set
    return body.machine_id, _effective_limit(matched, row.activation_limit)


async def _is_new_activation(session: AsyncSession, license_id: str, app_id: str, identity: str) -> bool:
    """True when no active (non-revoked) activation exists for this (license, app, identity) tuple."""
    result = await session.execute(
        select(DBActivation).where(
            DBActivation.license_id == license_id,
            DBActivation.app_id == app_id,
            DBActivation.identity == identity,
            DBActivation.revoked_at.is_(None),
        )
    )
    return result.scalar_one_or_none() is None


@router.post("/activate", response_model=ActivateResponse)
async def activate(body: ActivateRequest, request: Request) -> ActivateResponse:
    async with get_session() as session:
        row, matched = await _load_validated_license(session, body, request.app.state.signer)
        identity, limit = _resolve_identity_and_limit(body, row, matched)
        activation_app_id = matched.app_id if matched is not None else "*"

        if await _is_new_activation(session, body.license_id, activation_app_id, identity) and limit is not None:
            active_count = await count_active_activations(session, body.license_id, activation_app_id)
            if active_count >= limit:
                raise HTTPException(
                    status_code=403,
                    detail=f"Limit of {limit} reached for '{activation_app_id}'.",
                )

        await record_activation(session, body.license_id, activation_app_id, identity)
        final_count = await count_active_activations(session, body.license_id, activation_app_id)

    return ActivateResponse(
        status="activated",
        license_id=row.license_id,
        email=row.email,
        app_id=activation_app_id,
        limit=limit,
        active_count=final_count,
    )


@router.post("/deactivate", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate(body: DeactivateRequest, request: Request) -> None:
    """Release a seat. Required for floating licenses; optional for others."""
    async with get_session() as session:
        row = await get_license(session, body.license_id)
        if row is None:
            raise HTTPException(status_code=404, detail="License not found.")

        restriction = row.restriction
        if restriction == RestrictionMode.USERS.value:
            if not body.user_principal:
                raise HTTPException(status_code=422, detail="user_principal is required.")
            identity = body.user_principal
        else:
            if not body.machine_id:
                raise HTTPException(status_code=422, detail="machine_id is required.")
            identity = body.machine_id

        ok = await revoke_activation(session, body.license_id, body.app_id, identity)
        if not ok:
            raise HTTPException(status_code=404, detail="Active activation not found.")
