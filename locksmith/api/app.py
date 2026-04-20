"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from locksmith.core.config import settings
from locksmith.core.keys import FileSigner
from locksmith.core.store import create_tables, init_db

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def _default_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db(settings.db_url)
    await create_tables()
    app.state.signer = FileSigner.from_files(
        pubkey_path=settings.pubkey_path,
        privkey_path=(
            settings.privkey_path if settings.privkey_path.exists() else None
        ),
    )
    yield


def create_app(lifespan=None) -> FastAPI:
    """Application factory. Pass ``lifespan`` to override startup/shutdown (e.g. tests)."""
    app = FastAPI(
        title="Locksmith",
        version="0.1.0",
        description="Cross-platform software license validation backend.",
        lifespan=lifespan or _default_lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    from locksmith.api.routes.admin import router as admin_router
    from locksmith.api.routes.activate import router as activate_router
    from locksmith.api.routes.validate import router as validate_router

    app.include_router(admin_router, prefix="/licenses", tags=["admin"])
    app.include_router(activate_router, tags=["client"])
    app.include_router(validate_router, tags=["client"])

    @app.get("/health", tags=["ops"])
    async def health() -> dict:
        return {"status": "ok"}

    return app


def serve() -> None:
    """Entry point for ``locksmith-serve``."""
    import uvicorn

    uvicorn.run(
        "locksmith.api.app:create_app",
        factory=True,
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
