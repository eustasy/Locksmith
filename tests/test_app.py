"""Tests for the FastAPI application factory, default lifespan, and serve entrypoint."""

from __future__ import annotations

import pytest

import locksmith.api.app as app_module
import locksmith.core.store as store
from locksmith.core.keys import FileSigner, save_keypair


def test_create_app_wires_routes_and_limiter():
    app = app_module.create_app()
    # FastAPI >=0.137 includes routers lazily (`_IncludedRouter` placeholders in
    # `app.routes` have no `.path`), so read the paths off the OpenAPI schema.
    paths = set(app.openapi()["paths"])
    assert {"/health", "/activate", "/deactivate", "/validate", "/request"} <= paths
    assert any(p.startswith("/licenses") for p in paths)
    assert app.state.limiter is app_module.limiter


@pytest.mark.asyncio
async def test_default_lifespan_initializes_db_and_signer(keypair, tmp_path, monkeypatch):
    """The default lifespan inits the DB, creates tables, and loads the signer from settings."""
    pub, priv = keypair
    privf, pubf = save_keypair(pub, priv, tmp_path / "keys")

    monkeypatch.setattr(app_module.settings, "db_url", f"sqlite+aiosqlite:///{tmp_path}/lifespan.db")
    monkeypatch.setattr(app_module.settings, "pubkey_path", pubf)
    monkeypatch.setattr(app_module.settings, "privkey_path", privf)
    # init_db() reassigns these module globals; capture-and-restore so the shared
    # in-memory test DB used by other tests is left untouched.
    monkeypatch.setattr(store, "_engine", store._engine, raising=False)
    monkeypatch.setattr(store, "_async_session", store._async_session, raising=False)

    application = app_module.create_app()
    async with app_module._default_lifespan(application):
        assert isinstance(application.state.signer, FileSigner)


def test_serve_invokes_uvicorn(monkeypatch):
    import uvicorn

    calls = {}

    def _fake_run(app_path, **kwargs):
        calls["app_path"] = app_path
        calls["kwargs"] = kwargs

    monkeypatch.setattr(uvicorn, "run", _fake_run)
    app_module.serve()

    assert calls["app_path"] == "locksmith.api.app:create_app"
    assert calls["kwargs"]["factory"] is True
    assert calls["kwargs"]["host"] == app_module.settings.host
    assert calls["kwargs"]["port"] == app_module.settings.port
