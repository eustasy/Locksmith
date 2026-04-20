"""Offline validation and license request submission endpoints.

``POST /validate`` — accepts a ``.lic`` file upload and verifies the signature
    and business rules without touching the database. Suitable for air-gapped
    environments where the client cannot call ``/activate``.

``POST /request`` — accepts a ``.lsreq`` file upload and queues it for vendor
    review. No authentication required; the vendor uses the admin CLI to
    fulfil pending requests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status

from locksmith.api.schemas import ValidateResponse
from locksmith.core.license import License, LicenseRequest
from locksmith.core.signer import LicenseError, validate_license
from locksmith.core.store import get_session, save_request

router = APIRouter()

_MAX_UPLOAD_BYTES = 64 * 1024  # 64 KB — more than enough for any license file


def _check_extension(filename: str | None, expected: str) -> None:
    suffix = Path(filename or "").suffix.lower()
    if suffix != expected:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid file type '{suffix}'. Expected '{expected}'.",
        )


@router.post("/validate", response_model=ValidateResponse)
async def validate_offline(
    request: Request,
    file: UploadFile = File(...),
    app_version: str = Form(default=""),
    app_id: str = Form(default=""),
    edition: str = Form(default=""),
    platform: str = Form(default=""),
) -> ValidateResponse:
    """Verify a ``.lic`` file's signature and validity rules offline."""
    _check_extension(file.filename, ".lic")

    content = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large.")

    try:
        lic = License.from_json(content.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=422, detail="Could not parse license file.")

    try:
        from locksmith.core.license import Entitlement as _Ent

        matched: Optional[_Ent] = await validate_license(
            lic,
            request.app.state.signer,
            app_id=app_id or None,
            app_version=app_version or None,
            edition=edition or None,
            platform=platform or None,
        )
    except LicenseError as exc:
        return ValidateResponse(
            valid=False,
            license_id=lic.license_id,
            time_policy=lic.time_policy.value,
            version_policy=lic.version_policy.value,
            email=lic.email,
            expires_at=lic.expires_at,
            error=str(exc),
        )

    return ValidateResponse(
        valid=True,
        license_id=lic.license_id,
        time_policy=lic.time_policy.value,
        version_policy=lic.version_policy.value,
        email=lic.email,
        expires_at=lic.expires_at,
        matched_app_id=matched.app_id if matched is not None else None,
    )


@router.post("/request", status_code=status.HTTP_202_ACCEPTED)
async def submit_request(file: UploadFile = File(...)) -> dict:
    """Queue a customer ``.lsreq`` file for vendor review."""
    _check_extension(file.filename, ".lsreq")

    content = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large.")

    try:
        req = LicenseRequest.from_json(content.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=422, detail="Could not parse request file.")

    async with get_session() as session:
        await save_request(session, req)

    return {"status": "queued", "email": req.email}
