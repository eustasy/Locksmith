"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
import rsa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from locksmith.core.keys import FileSigner
from locksmith.core.store import Base


@pytest.fixture(scope="session")
def keypair() -> tuple[rsa.PrivateKey, rsa.PublicKey]:
    """Generate a small (1024-bit) keypair once per test session for speed."""
    pubkey, privkey = rsa.newkeys(1024)
    return privkey, pubkey


@pytest.fixture(scope="session")
def file_signer(keypair) -> FileSigner:
    privkey, pubkey = keypair
    return FileSigner(privkey=privkey, pubkey=pubkey)


@pytest.fixture(scope="session")
def verify_only_signer(keypair) -> FileSigner:
    _, pubkey = keypair
    return FileSigner(privkey=None, pubkey=pubkey)


@pytest.fixture(scope="session")
def test_db():
    """In-memory SQLite engine, shared for the session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.get_event_loop().run_until_complete(_setup())
    return engine


@pytest.fixture(scope="session")
def test_app(keypair, test_db):
    import locksmith.core.store as _store
    from locksmith.api.app import create_app

    privkey, pubkey = keypair
    session_factory = async_sessionmaker(test_db, expire_on_commit=False)

    # Wire the test engine into the store module so get_session() works
    _store._engine = test_db
    _store._async_session = session_factory

    @asynccontextmanager
    async def _lifespan(app):
        app.state.session_factory = session_factory
        app.state.signer = FileSigner(privkey=privkey, pubkey=pubkey)
        yield

    app = create_app(lifespan=_lifespan)
    # Pre-populate state for transports that don't trigger lifespan (e.g. ASGITransport)
    app.state.session_factory = session_factory
    app.state.signer = FileSigner(privkey=privkey, pubkey=pubkey)
    return app
