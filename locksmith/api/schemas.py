"""Pydantic v2 schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class EntitlementSchema(BaseModel):
    """Per-application constraint to embed in a license.

    All restriction fields are optional — omit to mean *use the license-level value*.
    ``platforms`` values are freeform strings, e.g. ``"windows"``, ``"macos"``,
    ``"windows_server_2022"``.
    """

    app_id: str
    editions: list[str] | None = None
    min_version: str | None = None
    max_version: str | None = None
    platforms: list[str] | None = None
    seats: int | None = Field(default=None, ge=1, le=10_000)


class IssueRequest(BaseModel):
    email: EmailStr
    valid_from: datetime

    # Time
    time_policy: str = "perpetual"  # "perpetual" | "limited"
    expires_at: datetime | None = None

    # Version
    version_policy: str = "any"  # "any" | "maintenance" | "specific"
    major_version: int | None = None
    locked_version: str | None = None

    # Edition / Platform (top-level defaults; entitlement-level can override)
    editions: list[str] | None = None
    platforms: list[str] | None = None

    # Restriction
    restriction: str | None = None  # "activations" | "users" | "floating"
    activation_limit: int | None = Field(default=None, ge=1, le=10_000)
    user_limit: int | None = Field(default=None, ge=1, le=10_000)
    concurrent_limit: int | None = Field(default=None, ge=1, le=10_000)

    # Per-application entitlements
    entitlements: list[EntitlementSchema] = []


class ActivateRequest(BaseModel):
    license_id: str
    machine_id: str | None = None  # for activations / floating restriction
    user_principal: str | None = None  # for users restriction
    app_id: str
    app_version: str
    edition: str | None = None
    platform: str | None = None


class ActivateResponse(BaseModel):
    status: str
    license_id: str
    email: str
    app_id: str
    limit: int | None
    active_count: int


class DeactivateRequest(BaseModel):
    license_id: str
    machine_id: str | None = None
    user_principal: str | None = None
    app_id: str


class ValidateResponse(BaseModel):
    valid: bool
    license_id: str | None = None
    email: str | None = None
    time_policy: str | None = None
    version_policy: str | None = None
    expires_at: datetime | None = None
    matched_app_id: str | None = None
    error: str | None = None


class LicenseMetadata(BaseModel):
    license_id: str
    email: str
    issued_at: datetime
    valid_from: datetime
    time_policy: str
    expires_at: datetime | None
    version_policy: str
    major_version: int | None
    locked_version: str | None
    editions: list[str] | None
    platforms: list[str] | None
    restriction: str | None
    activation_limit: int | None
    user_limit: int | None
    concurrent_limit: int | None
    entitlements: list[EntitlementSchema]
    revoked: bool
    active_count: int
