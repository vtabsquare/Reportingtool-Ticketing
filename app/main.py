from __future__ import annotations

import asyncio
import hmac
import json
import mimetypes
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db
from .config import ROOT, settings
from .security import Actor, current_actor, require_role, sign_payload, verify_payload
from .state_machine import validate_transition

app = FastAPI(title="VTAB Ticket Center", version="1.0.0")
if not settings.use_supabase_storage:
    settings.asset_dir.mkdir(parents=True, exist_ok=True)
db.initialize()

CATEGORIES = {"bug", "crash", "ui", "performance", "feature"}
SEVERITIES = {"low", "medium", "high", "critical"}
ROLES = {"user", "developer", "admin"}
SOURCE_ALIASES = {
    "exe": "exe",
    "desktop": "exe",
    "desktop_exe": "exe",
    "desktop-exe": "exe",
    "services": "services",
    "reporting-services": "services",
    "reporting_services": "services",
    "admin": "admin-console",
    "admin-console": "admin-console",
    "admin_console": "admin-console",
    "admin console": "admin-console",
}


def normalize_source(value: str | None, default: str = "services") -> str:
    raw = (value or "").strip().lower()
    if raw in SOURCE_ALIASES:
        return SOURCE_ALIASES[raw]
    return raw or default


class DiagnosticRequest(BaseModel):
    app_version: str
    os_info: dict[str, Any] = Field(default_factory=dict)
    workspace_id: str | None = None
    session_user: str
    recent_errors: str | None = None
    source: str | None = None


class IntegrationLinkRequest(BaseModel):
    user_id: str | None = None
    email: str | None = None
    role: str = "user"
    app_version: str = "unknown"
    os_info: dict[str, Any] = Field(default_factory=dict)
    workspace_id: str | None = None
    recent_errors: str | None = None
    source: str = "services"
    open_view: str | None = "submit"


class TicketCreate(BaseModel):
    title: str = Field(min_length=4, max_length=255)
    description: str = Field(min_length=10)
    steps_to_reproduce: str | None = None
    category: str = "bug"
    severity: str = "medium"
    source: str = "web"
    app_version: str = "unknown"
    os_info: dict[str, Any] = Field(default_factory=dict)
    diagnostic_logs: str | None = None
    workspace_id: str | None = None
    diagnostic_token: str | None = None


class AssignmentRequest(BaseModel):
    developer_id: str
    priority: str | None = None


class TransitionRequest(BaseModel):
    status: str
    notes: str | None = None
    fixed_in_build: str | None = None
    commit_reference: str | None = None
    user_experience_verified: bool = False
    user_satisfaction_rating: int | None = Field(default=None, ge=1, le=5)


class CommentRequest(BaseModel):
    body: str = Field(min_length=1, max_length=10000)
    is_internal: bool = False


def _storage_headers(content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {settings.supabase_service_role_key}",
        "apikey": settings.supabase_service_role_key,
    }
    if content_type:
        headers["Content-Type"] = content_type
        headers["x-upsert"] = "true"
    return headers


def _upload_to_supabase_storage(object_key: str, content: bytes, content_type: str) -> None:
    encoded = urllib.parse.quote(object_key, safe="/")
    url = f"{settings.supabase_url}/storage/v1/object/ticket-assets/{encoded}"
    req = urllib.request.Request(url, data=content, method="POST", headers=_storage_headers(content_type))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HTTPException(502, f"Supabase storage upload failed: {detail}") from exc
    except Exception as exc:
        raise HTTPException(502, "Supabase storage is currently unavailable.") from exc


def _download_from_supabase_storage(object_key: str) -> tuple[bytes, str]:
    encoded = urllib.parse.quote(object_key, safe="/")
    url = f"{settings.supabase_url}/storage/v1/object/ticket-assets/{encoded}"
    req = urllib.request.Request(url, method="GET", headers=_storage_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content_type = resp.headers.get("Content-Type") or mimetypes.guess_type(object_key)[0] or "application/octet-stream"
            return resp.read(), content_type
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(404, "Attachment not found.") from exc
        raise HTTPException(502, "Could not fetch attachment from Supabase storage.") from exc
    except Exception as exc:
        raise HTTPException(502, "Supabase storage is currently unavailable.") from exc


def get_ticket_or_404(ticket_id: str) -> dict[str, Any]:
    ticket = db.one("SELECT * FROM tickets WHERE id=?", (ticket_id,))
    if not ticket:
        raise HTTPException(404, "Ticket not found.")
    return db.hydrate_ticket(ticket)


def enforce_ticket_visibility(ticket: dict[str, Any], actor: Actor) -> None:
    if settings.auth_mode != "development" and actor.role == "user" and ticket["reporter_user_id"] != actor.user_id and ticket["reporter_email"].lower() != actor.email.lower():
        raise HTTPException(403, "You can only view your own tickets.")


def ticket_bundle(ticket_id: str, actor: Actor) -> dict[str, Any]:
    ticket = get_ticket_or_404(ticket_id)
    enforce_ticket_visibility(ticket, actor)
    timeline = db.many("SELECT * FROM ticket_timeline WHERE ticket_id=? ORDER BY created_at", (ticket_id,))
    comments = db.many(
        "SELECT * FROM ticket_comments WHERE ticket_id=? AND (?!='user' OR NOT is_internal) ORDER BY created_at",
        (ticket_id, actor.role),
    )
    attachments = db.many("SELECT * FROM ticket_attachments WHERE ticket_id=? ORDER BY created_at", (ticket_id,))
    return {"ticket": ticket, "timeline": timeline, "comments": comments, "attachments": attachments}


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "VTAB Ticket Center",
        "version": "1.0.0",
        "environment": settings.environment,
        "storage_backend": settings.storage_backend,
        "supabase_storage": settings.use_supabase_storage,
    }


@app.post("/api/integrations/link")
def create_integration_link(
    payload: IntegrationLinkRequest,
    x_vtab_integration_key: str | None = Header(default=None),
):
    if not settings.integration_key:
        raise HTTPException(503, "VTAB Ticket Center integration key is not configured.")
    if not x_vtab_integration_key or not hmac.compare_digest(x_vtab_integration_key.strip(), settings.integration_key):
        raise HTTPException(401, "Invalid integration key.")
    role = (payload.role or "user").strip().lower()
    if role not in ROLES:
        raise HTTPException(422, "Unsupported ticket role.")
    email = (payload.email or payload.user_id or f"{role}@vtab.local").strip().lower()
    user_id = (payload.user_id or email).strip()
    source = normalize_source(payload.source)
    auth_token = sign_payload(
        {"kind": "auth", "sub": user_id, "email": email, "role": role, "source": source},
        ttl_seconds=3600,
    )
    params = {"ticket_token": auth_token, "source": source}
    if payload.open_view:
        params["view"] = payload.open_view
    if payload.app_version or payload.workspace_id or payload.recent_errors or payload.os_info:
        diag_token = sign_payload(
            {
                "kind": "diagnostic",
                "app_version": payload.app_version,
                "os_info": payload.os_info or {},
                "workspace_id": payload.workspace_id,
                "session_user": email,
                "recent_errors": payload.recent_errors,
                "source": source,
            },
            ttl_seconds=3600,
        )
        params["diagnostic_token"] = diag_token
    query = urllib.parse.urlencode(params)
    return {"url": f"{settings.public_url}/?{query}", "role": role, "email": email, "source": source}


@app.post("/api/diagnostics/session")
def create_diagnostic_session(payload: DiagnosticRequest):
    token = sign_payload({"kind": "diagnostic", **payload.model_dump()})
    return {"token": token, "report_url": f"{settings.public_url}/?diagnostic_token={token}"}


@app.get("/api/diagnostics/{token}")
def read_diagnostic_session(token: str):
    payload = verify_payload(token)
    if payload.get("kind") != "diagnostic":
        raise HTTPException(400, "Not a diagnostic handoff token.")
    payload.pop("exp", None)
    return payload


@app.post("/api/tickets")
def create_ticket(payload: TicketCreate, actor: Actor = Depends(current_actor)):
    if payload.category not in CATEGORIES or payload.severity not in SEVERITIES:
        raise HTTPException(422, "Unsupported category or severity.")
    values = payload.model_dump()
    if payload.diagnostic_token:
        try:
            diagnostics = verify_payload(payload.diagnostic_token, allow_expired=True)
        except HTTPException:
            diagnostics = {}
        if diagnostics and diagnostics.get("kind") != "diagnostic":
            raise HTTPException(400, "Invalid diagnostic token.")
        for key in ("app_version", "os_info", "workspace_id", "recent_errors"):
            if diagnostics.get(key):
                target = "diagnostic_logs" if key == "recent_errors" else key
                values[target] = diagnostics[key]
        if diagnostics.get("source"):
            values["source"] = diagnostics["source"]
    if actor.source:
        values["source"] = actor.source
    ticket_id = str(uuid.uuid4())
    created = db.now()
    with db.LOCK, db.connect() as connection:
        number = db.next_ticket_number(connection)
        connection.execute(
            """INSERT INTO tickets(id,ticket_number,title,description,steps_to_reproduce,category,severity,status,source,app_version,os_info,diagnostic_logs,workspace_id,reporter_user_id,reporter_email,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ticket_id,
                number,
                values["title"].strip(),
                values["description"].strip(),
                values.get("steps_to_reproduce"),
                values["category"],
                values["severity"],
                "NEW",
                normalize_source(values.get("source")),
                values.get("app_version") or "unknown",
                json.dumps(values.get("os_info") or {}),
                values.get("diagnostic_logs"),
                values.get("workspace_id"),
                actor.user_id,
                actor.email,
                created,
                created,
            ),
        )
        db.add_timeline(connection, ticket_id, actor.user_id, actor.role, "created", None, "NEW", "Ticket submitted")
        connection.commit()
    return ticket_bundle(ticket_id, actor)


@app.get("/api/tickets")
def list_tickets(status: str | None = None, severity: str | None = None, search: str | None = None, mine: bool = False, actor: Actor = Depends(current_actor)):
    clauses, values = [], []
    if mine or (settings.auth_mode != "development" and actor.role == "user"):
        clauses.append("(reporter_user_id=? OR lower(reporter_email)=lower(?))")
        values.extend((actor.user_id, actor.email))
    if status:
        clauses.append("status=?")
        values.append(status)
    if severity:
        clauses.append("severity=?")
        values.append(severity)
    if search:
        clauses.append("(lower(title) LIKE ? OR CAST(ticket_number AS TEXT) LIKE ?)")
        values.extend((f"%{search.lower()}%", f"%{search}%"))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return [db.hydrate_ticket(item) for item in db.many("SELECT * FROM tickets" + where + " ORDER BY updated_at DESC", tuple(values))]


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: str, actor: Actor = Depends(current_actor)):
    return ticket_bundle(ticket_id, actor)


@app.post("/api/tickets/{ticket_id}/assign")
def assign_ticket(ticket_id: str, payload: AssignmentRequest, actor: Actor = Depends(current_actor)):
    require_role(actor, "developer", "admin")
    ticket = get_ticket_or_404(ticket_id)
    old_status = ticket["status"]
    if old_status not in {"NEW", "ASSIGNED"}:
        raise HTTPException(409, "Only new or assigned tickets can be reassigned.")
    updated = db.now()
    with db.LOCK, db.connect() as connection:
        connection.execute("UPDATE tickets SET assigned_dev_id=?,status='ASSIGNED',updated_at=? WHERE id=?", (payload.developer_id, updated, ticket_id))
        db.add_timeline(connection, ticket_id, actor.user_id, actor.role, "assigned", old_status, "ASSIGNED", f"Assigned to {payload.developer_id}")
        connection.commit()
    return ticket_bundle(ticket_id, actor)


@app.post("/api/tickets/{ticket_id}/transition")
def transition_ticket(ticket_id: str, payload: TransitionRequest, actor: Actor = Depends(current_actor)):
    require_role(actor, "developer", "admin")
    ticket = get_ticket_or_404(ticket_id)
    requested = payload.status.upper()
    data = payload.model_dump()
    validate_transition(ticket["status"], requested, actor.role, data)
    updated = db.now()
    fields: dict[str, Any] = {"status": requested, "updated_at": updated}
    if requested == "PENDING_ADMIN_SIGN_OFF":
        fields.update(dev_resolved_at=updated, dev_resolution_notes=payload.notes, fixed_in_build=payload.fixed_in_build, commit_reference=payload.commit_reference)
    elif requested == "REOPENED":
        fields.update(admin_reviewed_by=actor.user_id, admin_feedback_notes=payload.notes, user_experience_verified=False)
    elif requested == "CLOSED":
        fields.update(admin_reviewed_by=actor.user_id, admin_closed_at=updated, admin_feedback_notes=payload.notes, user_experience_verified=True, user_satisfaction_rating=payload.user_satisfaction_rating)
    columns = ",".join(f"{key}=?" for key in fields)
    with db.LOCK, db.connect() as connection:
        if settings.storage_backend == "supabase-postgresql":
            connection.execute("SELECT set_config('app.ticket_actor_role', ?, true)", (actor.role,))
        connection.execute(f"UPDATE tickets SET {columns} WHERE id=?", (*fields.values(), ticket_id))
        db.add_timeline(connection, ticket_id, actor.user_id, actor.role, "status_changed", ticket["status"], requested, payload.notes)
        connection.commit()
    return ticket_bundle(ticket_id, actor)


@app.post("/api/tickets/{ticket_id}/comments")
def add_comment(ticket_id: str, payload: CommentRequest, actor: Actor = Depends(current_actor)):
    ticket = get_ticket_or_404(ticket_id)
    enforce_ticket_visibility(ticket, actor)
    if actor.role == "user" and payload.is_internal:
        raise HTTPException(403, "Reporters cannot create internal notes.")
    comment_id = str(uuid.uuid4())
    created = db.now()
    with db.LOCK, db.connect() as connection:
        connection.execute(
            "INSERT INTO ticket_comments(id,ticket_id,author_id,author_role,body,is_internal,created_at) VALUES(?,?,?,?,?,?,?)",
            (comment_id, ticket_id, actor.user_id, actor.role, payload.body.strip(), bool(payload.is_internal), created),
        )
        db.add_timeline(connection, ticket_id, actor.user_id, actor.role, "commented", ticket["status"], ticket["status"], "Internal note" if payload.is_internal else "Comment added")
        connection.execute("UPDATE tickets SET updated_at=? WHERE id=?", (created, ticket_id))
        connection.commit()
    return ticket_bundle(ticket_id, actor)


@app.post("/api/tickets/{ticket_id}/attachments")
async def add_attachment(ticket_id: str, file: UploadFile = File(...), actor: Actor = Depends(current_actor)):
    ticket = get_ticket_or_404(ticket_id)
    enforce_ticket_visibility(ticket, actor)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(file.filename or "attachment").name)[:180]
    attachment_id = str(uuid.uuid4())
    object_name = f"{attachment_id}_{safe_name}"
    chunks: list[bytes] = []
    size = 0
    while chunk := await file.read(1024 * 1024):
        size += len(chunk)
        if size > settings.max_upload_mb * 1024 * 1024:
            raise HTTPException(413, f"Attachment exceeds {settings.max_upload_mb} MB.")
        chunks.append(chunk)
    content = b"".join(chunks)
    mime = file.content_type or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"

    if settings.use_supabase_storage:
        object_key = f"{ticket_id}/{object_name}"
        _upload_to_supabase_storage(object_key, content, mime)
        url = f"/assets/{object_key}"
    else:
        settings.asset_dir.mkdir(parents=True, exist_ok=True)
        target = settings.asset_dir / object_name
        target.write_bytes(content)
        url = f"/assets/{object_name}"

    created = db.now()
    with db.LOCK, db.connect() as connection:
        connection.execute(
            "INSERT INTO ticket_attachments(id,ticket_id,file_name,file_url,file_type,file_size_bytes,uploaded_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (attachment_id, ticket_id, safe_name, url, mime, size, actor.user_id, created),
        )
        db.add_timeline(connection, ticket_id, actor.user_id, actor.role, "attachment_added", ticket["status"], ticket["status"], safe_name)
        connection.commit()
    return {"id": attachment_id, "file_name": safe_name, "file_url": url, "file_type": mime, "file_size_bytes": size}


@app.get("/api/events")
async def events(request: Request, actor: Actor = Depends(current_actor)):
    async def stream():
        last = ""
        latest_expr = "COALESCE(MAX(updated_at)::text, '')" if settings.storage_backend == "supabase-postgresql" else "COALESCE(MAX(updated_at), '')"
        while not await request.is_disconnected():
            query = f"SELECT {latest_expr} AS latest, COUNT(*) AS count FROM tickets"
            values: tuple = ()
            if actor.role == "user":
                query += " WHERE reporter_user_id=? OR lower(reporter_email)=lower(?)"
                values = (actor.user_id, actor.email)
            try:
                snapshot = db.one(query, values) or {"latest": "", "count": 0}
            except Exception:
                snapshot = {"latest": "", "count": 0}
            encoded = json.dumps(snapshot, separators=(",", ":"))
            if encoded != last:
                yield f"event: tickets\ndata: {encoded}\n\n"
                last = encoded
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(4)
    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.get("/assets/{object_key:path}")
def get_ticket_asset(object_key: str):
    if settings.use_supabase_storage:
        content, content_type = _download_from_supabase_storage(object_key)
        return Response(content=content, media_type=content_type)
    base = settings.asset_dir.resolve()
    target = (base / object_key).resolve()
    if base not in target.parents or not target.is_file():
        raise HTTPException(404, "Attachment not found.")
    return FileResponse(target)


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/{path:path}")
def frontend(path: str):
    candidate = ROOT / "static" / path
    if path and candidate.is_file():
        return FileResponse(candidate)
    return FileResponse(ROOT / "static" / "index.html")
