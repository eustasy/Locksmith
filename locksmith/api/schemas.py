"""Pydantic v2 schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class EntitlementSchema(BaseModel):
    """Per-application constraint to embed in a license.

    All restriction fields are optional — omit to mean *use the license-level value*.
    ``platforms`` values are freeform strings, e.g. ``"windows"``, ``"macos"``,
    ``"windows_server_2022"``.
    """

    app_id: str
    editions: Optional[list[str]] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    platforms: Optional[list[str]] = None
    seats: Optional[int] = Field(default=None, ge=1, le=10_000)


class IssueRequest(BaseModel):
    email: EmailStr
    valid_from: datetime

    # Time
    time_policy: str = "perpetual"  # "perpetual" | "limited"
    expires_at: Optional[datetime] = None

    # Version
    version_policy: str = "any"  # "any" | "maintenance" | "specific"
    major_version: Optional[int] = None
    locked_version: Optional[str] = None

    # Edition / Platform (top-level defaults; entitlement-level can override)
    editions: Optional[list[str]] = None
    platforms: Optional[list[str]] = None

    # Restriction
    restriction: Optional[str] = None  # "activations" | "users" | "floating"
    activation_limit: Optional[int] = Field(default=None, ge=1, le=10_000)
    user_limit: Optional[int] = Field(default=None, ge=1, le=10_000)
    concurrent_limit: Optional[int] = Field(default=None, ge=1, le=10_000)

    # Per-application entitlements
    entitlements: list[EntitlementSchema] = []


class ActivateRequest(BaseModel):
    license_id: str
    machine_id: Optional[str] = None  # for activations / floating restriction
    user_principal: Optional[str] = None  # for users restriction
    app_id: str
    app_version: str
    edition: Optional[str] = None
    platform: Optional[str] = None


class ActivateResponse(BaseModel):
    status: str
    license_id: str
    email: str
    app_id: str
    limit: Optional[int]
    active_count: int


class DeactivateRequest(BaseModel):
    license_id: str
    machine_id: Optional[str] = None
    user_principal: Optional[str] = None
    app_id: str


class ValidateResponse(BaseModel):
    valid: bool
    license_id: Optional[str] = None
    email: Optional[str] = None
    time_policy: Optional[str] = None
    version_policy: Optional[str] = None
    expires_at: Optional[datetime] = None
    matched_app_id: Optional[str] = None
    error: Optional[str] = None


class LicenseMetadata(BaseModel):
    license_id: str
    email: str
    issued_at: datetime
    valid_from: datetime
    time_policy: str
    expires_at: Optional[datetime]
    version_policy: str
    major_version: Optional[int]
    locked_version: Optional[str]
    editions: Optional[list[str]]
    platforms: Optional[list[str]]
    restriction: Optional[str]
    activation_limit: Optional[int]
    user_limit: Optional[int]
    concurrent_limit: Optional[int]
    entitlements: list[EntitlementSchema]
    revoked: bool
    active_count: int


from pydantic import BaseModel, Field
