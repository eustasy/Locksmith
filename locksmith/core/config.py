from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LOCKSMITH_",
        env_file=".env",
        extra="ignore",
    )

    privkey_path: Path = Path("keys/privkey.pem")
    pubkey_path: Path = Path("keys/pubkey.pem")
    admin_api_key: str = ""
    db_url: str = "sqlite+aiosqlite:///./locksmith.db"


settings = Settings()
