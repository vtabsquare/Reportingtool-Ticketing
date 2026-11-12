from __future__ import annotations

from fastapi import HTTPException

ALLOWED_TRANSITIONS = {
    "NEW": {"developer": {"ASSIGNED", "IN_PROGRESS"}, "admin": {"ASSIGNED", "IN_PROGRESS"}},
    "ASSIGNED": {"developer": {"IN_PROGRESS"}, "admin": {"IN_PROGRESS", "REOPENED"}},
    "IN_PROGRESS": {"developer": {"PENDING_ADMIN_SIGN_OFF"}, "admin": {"REOPENED"}},
    "RESOLVED_BY_DEV": {"developer": {"PENDING_ADMIN_SIGN_OFF"}, "admin": {"PENDING_ADMIN_SIGN_OFF", "REOPENED"}},
    "PENDING_ADMIN_SIGN_OFF": {"admin": {"CLOSED", "REOPENED"}},
    "REOPENED": {"developer": {"IN_PROGRESS", "PENDING_ADMIN_SIGN_OFF"}, "admin": {"IN_PROGRESS"}},
    "CLOSED": {},
}


def validate_transition(old_status: str, new_status: str, role: str, payload: dict) -> None:
    allowed = ALLOWED_TRANSITIONS.get(old_status, {}).get(role, set())
    if new_status not in allowed:
        raise HTTPException(409, f"{role} cannot move a ticket from {old_status} to {new_status}.")
    if new_status == "PENDING_ADMIN_SIGN_OFF":
        required = ("fixed_in_build", "commit_reference", "notes")
        missing = [key for key in required if not str(payload.get(key) or "").strip()]
        if missing:
            raise HTTPException(422, "Developer resolution requires fixed build, commit/PR reference and verification notes.")
    if new_status == "REOPENED" and not str(payload.get("notes") or "").strip():
        raise HTTPException(422, "Reopening requires feedback notes.")
    if new_status == "CLOSED":
        if payload.get("user_experience_verified") is not True:
            raise HTTPException(422, "Admin must verify the user experience before closing.")
        if not str(payload.get("notes") or "").strip():
            raise HTTPException(422, "Admin closure notes are required.")

