"""Database models and async repository functions.

Uses SQLAlchemy 2.x async with aiosqlite (SQLite default) or any
async-compatible database URL (e.g. asyncpg for PostgreSQL in production).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .license import License, LicenseRequest


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class DBLicense(Base):
    __tablename__ = "licenses"

    license_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Time
    time_policy: Mapped[str] = mapped_column(
        String(20), nullable=False, default="perpetual"
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Version
    version_policy: Mapped[str] = mapped_column(
        String(20), nullable=False, default="any"
    )
    major_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    locked_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # Edition / Platform (top-level defaults)
    editions_json: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    platforms_json: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Restriction
    restriction: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    activation_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    user_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    concurrent_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Per-application entitlements
    entitlements_json: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    signature: Mapped[str] = mapped_column(String(2048), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    activations: Mapped[list[DBActivation]] = relationship(
        back_populates="license", cascade="all, delete-orphan", lazy="noload"
    )


class DBActivation(Base):
    """Tracks a single machine, user, or concurrent session against a license.

    ``identity`` holds whichever identifier is appropriate for the restriction mode:
      - ``activations`` / ``floating`` → machine ID (SHA-256 hex)
      - ``users``                      → user principal (``DOMAIN\\username``)

    ``app_id`` is ``"*"`` for licenses with no entitlements (app-unrestricted).
    """

    __tablename__ = "activations"
    __table_args__ = (UniqueConstraint("license_id", "app_id", "identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("licenses.license_id", ondelete="CASCADE"),
        nullable=False,
    )
    app_id: Mapped[str] = mapped_column(String(255), nullable=False, default="*")
    identity: Mapped[str] = mapped_column(String(255), nullable=False)
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    license: Mapped[DBLicense] = relationship(
        back_populates="activations", lazy="noload"
    )


class DBLicenseRequest(Base):
    __tablename__ = "license_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    machine_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    app_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    app_version: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    fulfilled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


# ---------------------------------------------------------------------------
# Engine / session factory (module-level singletons)
# ---------------------------------------------------------------------------

_engine = None
_async_session: async_sessionmaker[AsyncSession] | None = None


def init_db(db_url: str) -> None:
    """Initialise the async engine. Call once at application startup."""
    global _engine, _async_session
    _engine = create_async_engine(db_url, echo=False)
    _async_session = async_sessionmaker(_engine, expire_on_commit=False)


async def create_tables() -> None:
    """Create all tables if they do not already exist."""
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def get_session() -> AsyncSession:
    """Return a new ``AsyncSession`` suitable for use as an async context manager."""
    if _async_session is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _async_session()


# ---------------------------------------------------------------------------
# Repository functions
# ---------------------------------------------------------------------------


async def save_license(session: AsyncSession, lic: License) -> DBLicense:
    row = DBLicense(
        license_id=lic.license_id,
        email=lic.email,
        issued_at=lic.issued_at,
        valid_from=lic.valid_from,
        time_policy=lic.time_policy.value,
        expires_at=lic.expires_at,
        version_policy=lic.version_policy.value,
        major_version=lic.major_version,
        locked_version=lic.locked_version,
        editions_json=lic.editions,
        platforms_json=lic.platforms,
        restriction=lic.restriction.value if lic.restriction else None,
        activation_limit=lic.activation_limit,
        user_limit=lic.user_limit,
        concurrent_limit=lic.concurrent_limit,
        entitlements_json=[e.to_dict() for e in lic.entitlements] or None,
        signature=lic.signature,
    )
    session.add(row)
    await session.commit()
    return row


async def get_license(session: AsyncSession, license_id: str) -> Optional[DBLicense]:
    result = await session.execute(
        select(DBLicense).where(DBLicense.license_id == license_id)
    )
    return result.scalar_one_or_none()


async def revoke_license(session: AsyncSession, license_id: str) -> bool:
    row = await get_license(session, license_id)
    if row is None:
        return False
    row.revoked = True
    await session.commit()
    return True


async def count_active_activations(
    session: AsyncSession, license_id: str, app_id: str = "*"
) -> int:
    result = await session.execute(
        select(func.count()).where(
            DBActivation.license_id == license_id,
            DBActivation.app_id == app_id,
            DBActivation.revoked_at.is_(None),
        )
    )
    return result.scalar_one()


async def record_activation(
    session: AsyncSession, license_id: str, app_id: str, identity: str
) -> DBActivation:
    """Record or reactivate an identity. Caller is responsible for limit checks."""
    result = await session.execute(
        select(DBActivation).where(
            DBActivation.license_id == license_id,
            DBActivation.app_id == app_id,
            DBActivation.identity == identity,
        )
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        if existing.revoked_at is not None:
            existing.revoked_at = None
            await session.commit()
        return existing

    row = DBActivation(
        license_id=license_id,
        app_id=app_id,
        identity=identity,
        activated_at=datetime.now(timezone.utc),
    )
    session.add(row)
    await session.commit()
    return row


async def revoke_activation(
    session: AsyncSession, license_id: str, app_id: str, identity: str
) -> bool:
    """Revoke a single activation (e.g. floating check-in). Returns False if not found."""
    result = await session.execute(
        select(DBActivation).where(
            DBActivation.license_id == license_id,
            DBActivation.app_id == app_id,
            DBActivation.identity == identity,
            DBActivation.revoked_at.is_(None),
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return False
    row.revoked_at = datetime.now(timezone.utc)
    await session.commit()
    return True


async def save_request(session: AsyncSession, req: LicenseRequest) -> DBLicenseRequest:
    row = DBLicenseRequest(
        email=req.email,
        machine_id=req.machine_id,
        app_id=req.app_id,
        app_version=req.app_version,
        requested_at=req.requested_at,
    )
    session.add(row)
    await session.commit()
    return row


from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .license import License, LicenseRequest


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------
