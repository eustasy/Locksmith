"""License data model and request file model.

License files (.lic) are signed JSON payloads. The signature covers all
fields except the ``signature`` key itself.

License request files (.lsreq) are unsigned JSON payloads that customers
generate and send to the vendor to initiate the issuance process.

A license is described by five independent dimensions:

  - **Time**: perpetual or limited (arbitrary expiry date).
  - **Version**: any, maintenance (major version only), or specific (exact version).
  - **Edition**: optional allowed-edition list, case-insensitive freeform strings.
  - **Platform**: optional allowed-OS list, freeform strings (e.g. ``"windows"``,
    ``"macos"``, ``"windows_server_2022"``).
  - **Restriction**: optional limit on how many machines / users / concurrent
    sessions may use the license.

A license may additionally contain per-application ``Entitlement`` records.
When present, a client must match one by ``app_id``. An entitlement can override
the license-level edition, platform, version-range, and seat count for that
specific application.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class TimePolicy(str, Enum):
    PERPETUAL = "perpetual"
    LIMITED = "limited"


class VersionPolicy(str, Enum):
    ANY = "any"
    MAINTENANCE = "maintenance"  # must share same major version as major_version
    SPECIFIC = "specific"  # must match locked_version exactly


class RestrictionMode(str, Enum):
    ACTIVATIONS = "activations"  # max N distinct machines
    USERS = "users"  # max N distinct named user principals
    FLOATING = "floating"  # max N concurrent sessions (check-out / check-in)


class Entitlement:
    """Per-application constraint embedded within a license.

    All restriction fields are optional — ``None`` means *use the license-level value*:

    - ``editions``    — allowed edition names (case-insensitive). ``None`` = use license-level.
    - ``min_version`` — inclusive minimum app version string, e.g. ``"2.0.0"``.
    - ``max_version`` — inclusive maximum app version string, e.g. ``"2.9.9"``.
    - ``platforms``   — allowed OS names (freeform, case-insensitive). ``None`` = use license-level.
    - ``seats``       — per-app limit override. ``None`` = use the license-level restriction limit.
    """

    def __init__(
        self,
        *,
        app_id: str,
        editions: Optional[list[str]] = None,
        min_version: Optional[str] = None,
        max_version: Optional[str] = None,
        platforms: Optional[list[str]] = None,
        seats: Optional[int] = None,
    ) -> None:
        self.app_id = app_id
        self.editions = [e.lower() for e in editions] if editions is not None else None
        self.min_version = min_version
        self.max_version = max_version
        self.platforms = (
            [p.lower() for p in platforms] if platforms is not None else None
        )
        self.seats = seats

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "editions": self.editions,
            "min_version": self.min_version,
            "max_version": self.max_version,
            "platforms": self.platforms,
            "seats": self.seats,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Entitlement:
        return cls(
            app_id=d["app_id"],
            editions=d.get("editions"),
            min_version=d.get("min_version"),
            max_version=d.get("max_version"),
            platforms=d.get("platforms"),
            seats=d.get("seats"),
        )


class License:
    """In-memory representation of a signed license."""

    def __init__(
        self,
        *,
        license_id: str,
        email: str,
        issued_at: datetime,
        valid_from: datetime,
        # Time
        time_policy: TimePolicy | str = TimePolicy.PERPETUAL,
        expires_at: Optional[datetime] = None,
        # Version
        version_policy: VersionPolicy | str = VersionPolicy.ANY,
        major_version: Optional[int] = None,
        locked_version: Optional[str] = None,
        # Edition / Platform (top-level defaults; entitlement-level can override)
        editions: Optional[list[str]] = None,
        platforms: Optional[list[str]] = None,
        # Restriction
        restriction: Optional[RestrictionMode | str] = None,
        activation_limit: Optional[int] = None,
        user_limit: Optional[int] = None,
        concurrent_limit: Optional[int] = None,
        # Per-application entitlements
        entitlements: Optional[list[Entitlement]] = None,
        signature: Optional[str] = None,
    ) -> None:
        self.license_id = license_id
        self.email = email
        self.issued_at = issued_at
        self.valid_from = valid_from
        self.time_policy = TimePolicy(time_policy)
        self.expires_at = expires_at
        self.version_policy = VersionPolicy(version_policy)
        self.major_version = major_version
        self.locked_version = locked_version
        self.editions = [e.lower() for e in editions] if editions is not None else None
        self.platforms = (
            [p.lower() for p in platforms] if platforms is not None else None
        )
        self.restriction = (
            RestrictionMode(restriction) if restriction is not None else None
        )
        self.activation_limit = activation_limit
        self.user_limit = user_limit
        self.concurrent_limit = concurrent_limit
        self.entitlements: list[Entitlement] = entitlements or []
        self.signature = signature

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def signable_payload(self) -> bytes:
        """Canonical UTF-8 bytes covered by the signature.

        The ``signature`` field is intentionally excluded so the payload
        is stable before and after signing.
        """
        d = {
            "license_id": self.license_id,
            "email": self.email,
            "issued_at": self.issued_at.isoformat(),
            "valid_from": self.valid_from.isoformat(),
            "time_policy": self.time_policy.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "version_policy": self.version_policy.value,
            "major_version": self.major_version,
            "locked_version": self.locked_version,
            "editions": self.editions,
            "platforms": self.platforms,
            "restriction": self.restriction.value if self.restriction else None,
            "activation_limit": self.activation_limit,
            "user_limit": self.user_limit,
            "concurrent_limit": self.concurrent_limit,
            "entitlements": [e.to_dict() for e in self.entitlements],
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        d = json.loads(self.signable_payload())
        d["signature"] = self.signature
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_file(self, path: Path | str) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> License:
        def _dt(v: str | None) -> datetime | None:
            return datetime.fromisoformat(v) if v else None

        entitlements = [Entitlement.from_dict(e) for e in d.get("entitlements", [])]
        return cls(
            license_id=d["license_id"],
            email=d["email"],
            issued_at=datetime.fromisoformat(d["issued_at"]),
            valid_from=datetime.fromisoformat(d["valid_from"]),
            time_policy=d.get("time_policy", TimePolicy.PERPETUAL),
            expires_at=_dt(d.get("expires_at")),
            version_policy=d.get("version_policy", VersionPolicy.ANY),
            major_version=d.get("major_version"),
            locked_version=d.get("locked_version"),
            editions=d.get("editions"),
            platforms=d.get("platforms"),
            restriction=d.get("restriction"),
            activation_limit=d.get("activation_limit"),
            user_limit=d.get("user_limit"),
            concurrent_limit=d.get("concurrent_limit"),
            entitlements=entitlements,
            signature=d.get("signature"),
        )

    @classmethod
    def from_json(cls, text: str) -> License:
        return cls.from_dict(json.loads(text))

    @classmethod
    def from_file(cls, path: Path | str) -> License:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# License request
# ---------------------------------------------------------------------------


class LicenseRequest:
    """Unsigned request file generated by the customer and sent to the vendor."""

    def __init__(
        self,
        *,
        email: str,
        machine_id: Optional[str],
        app_version: str,
        app_id: Optional[str] = None,
        requested_at: datetime,
    ) -> None:
        self.email = email
        self.machine_id = machine_id
        self.app_version = app_version
        self.app_id = app_id
        self.requested_at = requested_at

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "machine_id": self.machine_id,
            "app_id": self.app_id,
            "app_version": self.app_version,
            "requested_at": self.requested_at.isoformat(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_file(self, path: Path | str) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_dict(cls, d: dict) -> LicenseRequest:
        return cls(
            email=d["email"],
            machine_id=d.get("machine_id"),
            app_id=d.get("app_id"),
            app_version=d["app_version"],
            requested_at=datetime.fromisoformat(d["requested_at"]),
        )

    @classmethod
    def from_json(cls, text: str) -> LicenseRequest:
        return cls.from_dict(json.loads(text))

    @classmethod
    def from_file(cls, path: Path | str) -> LicenseRequest:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    @staticmethod
    def new(
        email: str,
        machine_id: Optional[str],
        app_version: str,
        app_id: Optional[str] = None,
    ) -> LicenseRequest:
        return LicenseRequest(
            email=email,
            machine_id=machine_id,
            app_id=app_id,
            app_version=app_version,
            requested_at=datetime.now(timezone.utc),
        )
