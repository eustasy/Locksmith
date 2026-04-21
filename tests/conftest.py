"""Shared pytest fixtures."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
import rsa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from locksmith.core.keys import FileSigner, generate_keypair
from locksmith.core import store


@pytest.fixture(scope="session")
def keypair() -> tuple[rsa.PublicKey, rsa.PrivateKey]:
    """Generate a 2048-bit keypair once per test session."""
    return generate_keypair(2048)


@pytest.fixture(scope="session")
def file_signer(keypair) -> FileSigner:
    pubkey, privkey = keypair
    return FileSigner(pubkey=pubkey, privkey=privkey)


@pytest.fixture(scope="session")
def verify_only_signer(keypair) -> FileSigner:
    pubkey, _ = keypair
    return FileSigner(privkey=None, pubkey=pubkey)


@pytest.fixture(scope="session")
def test_db():
    """In-memory SQLite engine, shared for the session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(store.Base.metadata.create_all)

    asyncio.run(_setup())
    return engine


@pytest.fixture(scope="session")
def test_app(keypair, test_db):
    from locksmith.api.app import create_app

    pubkey, privkey = keypair
    session_factory = async_sessionmaker(test_db, expire_on_commit=False)

    # Wire the test engine into the store module so get_session() works
    store._engine = test_db
    store._async_session = session_factory

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
