"""Admin API key authentication dependency."""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from locksmith.core.config import settings

_bearer = HTTPBearer()


async def require_admin(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> None:
    """Dependency — raises 401 if the bearer token does not match LOCKSMITH_ADMIN_API_KEY."""
    if not settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API key is not configured on this server.",
        )
    if credentials.credentials != settings.admin_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
