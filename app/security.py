from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException

from .config import settings


@dataclass(frozen=True)
class Actor:
    user_id: str
    email: str
    role: str
    source: str | None = None


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_payload(payload: dict[str, Any], ttl_seconds: int | None = None) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + int(ttl_seconds or settings.diagnostic_ttl_seconds)
    encoded = _encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    signature = _encode(hmac.new(settings.signing_secret.encode(), encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def verify_payload(token: str, *, allow_expired: bool = False) -> dict[str, Any]:
    try:
        encoded, signature = token.split(".", 1)
        expected = _encode(hmac.new(settings.signing_secret.encode(), encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        payload = json.loads(_decode(encoded))
        if not allow_expired and int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception as exc:
        raise HTTPException(400, "The diagnostic handoff link is invalid or expired.") from exc


def current_actor(
    x_vtab_ticket_token: str | None = Header(default=None),
    x_vtab_user: str | None = Header(default=None),
    x_vtab_user_id: str | None = Header(default=None),
    x_vtab_user_email: str | None = Header(default=None),
    x_vtab_role: str | None = Header(default=None),
) -> Actor:
    if x_vtab_ticket_token:
        payload = verify_payload(x_vtab_ticket_token)
        role = str(payload.get("role") or "user").strip().lower()
        if role not in {"user", "developer", "admin"}:
            raise HTTPException(403, "Unknown ticket role.")
        return Actor(
            str(payload.get("sub") or payload.get("email")),
            str(payload.get("email") or ""),
            role,
            str(payload.get("source")).strip() if payload.get("source") else None,
        )
    if settings.auth_mode == "development":
        email = (x_vtab_user_email or x_vtab_user or "reporter@vtab.local").strip().lower()
        user_id = (x_vtab_user_id or email).strip()
        role = (x_vtab_role or "user").strip().lower()
        if role not in {"user", "developer", "admin"}:
            raise HTTPException(403, "Unknown ticket role.")
        return Actor(user_id, email, role)
    raise HTTPException(401, "A signed VTAB Ticket token is required.")


def require_role(actor: Actor, *roles: str) -> None:
    if actor.role not in roles:
        raise HTTPException(403, f"This action requires: {', '.join(roles)}.")

