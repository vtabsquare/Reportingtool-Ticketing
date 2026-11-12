from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_env_file() -> None:
    path = ROOT / ".env"
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("VTAB_TICKET_ENV", "development")
    host: str = os.getenv("VTAB_TICKET_HOST", "127.0.0.1")
    port: int = int(os.getenv("VTAB_TICKET_PORT", "8860"))
    public_url: str = os.getenv("VTAB_TICKET_PUBLIC_URL", "http://127.0.0.1:8860").rstrip("/")
    auth_mode: str = os.getenv("VTAB_TICKET_AUTH_MODE", "development").lower()
    signing_secret: str = os.getenv("VTAB_TICKET_SIGNING_SECRET", "development-only-change-this-secret")
    integration_key: str = os.getenv("VTAB_TICKET_INTEGRATION_KEY", "").strip()
    diagnostic_ttl_seconds: int = int(os.getenv("VTAB_TICKET_DIAGNOSTIC_TTL_SECONDS", "900"))
    max_upload_mb: int = int(os.getenv("VTAB_TICKET_MAX_UPLOAD_MB", "50"))
    database_url: str = os.getenv("VTAB_TICKET_DATABASE_URL", os.getenv("DATABASE_URL", "")).strip()
    supabase_url: str = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    supabase_service_role_key: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

    @property
    def storage_backend(self) -> str:
        if self.database_url.startswith(("postgres://", "postgresql://")):
            return "supabase-postgresql"
        return "sqlite"

    @property
    def use_supabase_storage(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)

    @property
    def database_path(self) -> Path:
        raw = Path(os.getenv("VTAB_TICKET_DATABASE", "data/vtab_tickets.db"))
        return raw if raw.is_absolute() else ROOT / raw

    @property
    def asset_dir(self) -> Path:
        raw = Path(os.getenv("VTAB_TICKET_ASSET_DIR", "storage/ticket-assets"))
        return raw if raw.is_absolute() else ROOT / raw


settings = Settings()
