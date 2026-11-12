from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import settings

logger = logging.getLogger("vtab.ticket_center.db")
LOCK = threading.RLock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sql(query: str) -> str:
    """Translate SQLite `?` placeholders to PostgreSQL `%s` outside string literals."""
    if settings.storage_backend != "supabase-postgresql":
        return query
    out: list[str] = []
    in_single = False
    i = 0
    while i < len(query):
        ch = query[i]
        if ch == "'":
            out.append(ch)
            if in_single and i + 1 < len(query) and query[i + 1] == "'":
                out.append("'")
                i += 2
                continue
            in_single = not in_single
        elif ch == "?" and not in_single:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


class _PgConnection:
    """Thin adapter around psycopg connection matching sqlite3 context/execute usage."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, query: str, values: tuple = ()) -> Any:
        return self._conn.execute(_sql(query), values)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "_PgConnection":
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        try:
            return self._conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            self._conn.close()


def connect() -> Any:
    if settings.storage_backend == "supabase-postgresql":
        import psycopg
        from psycopg.rows import dict_row

        return _PgConnection(psycopg.connect(settings.database_url, row_factory=dict_row))

    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets(
 id TEXT PRIMARY KEY, ticket_number INTEGER UNIQUE, title TEXT NOT NULL, description TEXT NOT NULL,
 steps_to_reproduce TEXT, category TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
 source TEXT NOT NULL, app_version TEXT NOT NULL, os_info TEXT, diagnostic_logs TEXT, workspace_id TEXT,
 reporter_user_id TEXT NOT NULL, reporter_email TEXT NOT NULL, assigned_dev_id TEXT,
 dev_resolved_at TEXT, dev_resolution_notes TEXT, fixed_in_build TEXT, commit_reference TEXT,
 admin_reviewed_by TEXT, admin_closed_at TEXT, admin_feedback_notes TEXT,
 user_experience_verified INTEGER NOT NULL DEFAULT 0, user_satisfaction_rating INTEGER,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_attachments(
 id TEXT PRIMARY KEY, ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 file_name TEXT NOT NULL, file_url TEXT NOT NULL, file_type TEXT, file_size_bytes INTEGER,
 uploaded_by TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_timeline(
 id TEXT PRIMARY KEY, ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 actor_id TEXT NOT NULL, actor_role TEXT NOT NULL, event_type TEXT NOT NULL,
 old_status TEXT, new_status TEXT, notes TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ticket_comments(
 id TEXT PRIMARY KEY, ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 author_id TEXT NOT NULL, author_role TEXT NOT NULL, body TEXT NOT NULL, is_internal INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_reporter ON tickets(reporter_user_id);
CREATE INDEX IF NOT EXISTS idx_timeline_ticket ON ticket_timeline(ticket_id,created_at);
"""


def initialize() -> None:
    if settings.storage_backend == "supabase-postgresql":
        try:
            with connect() as db:
                row = db.execute("SELECT to_regclass('public.tickets') IS NOT NULL AS ready").fetchone()
                if not row or not row.get("ready"):
                    logger.warning(
                        "Supabase table public.tickets does not exist yet. "
                        "Run migrations/001_ticket_center_supabase.sql in Supabase SQL Editor."
                    )
        except Exception as exc:
            logger.warning("Could not verify Supabase ticket schema during startup: %s", exc)
        return

    with LOCK, connect() as db:
        try:
            db.executescript(SCHEMA)
        finally:
            db.close()


def _serialize_row(row: Any) -> dict[str, Any]:
    item = dict(row)
    for key, value in list(item.items()):
        if isinstance(value, datetime):
            item[key] = value.isoformat()
        elif isinstance(value, uuid.UUID):
            item[key] = str(value)
    return item


def one(query: str, values: tuple = ()) -> dict[str, Any] | None:
    with connect() as db:
        try:
            row = db.execute(query, values).fetchone()
        finally:
            if settings.storage_backend != "supabase-postgresql":
                db.close()
    return _serialize_row(row) if row else None


def many(query: str, values: tuple = ()) -> list[dict[str, Any]]:
    with connect() as db:
        try:
            rows = db.execute(query, values).fetchall()
        finally:
            if settings.storage_backend != "supabase-postgresql":
                db.close()
    return [_serialize_row(row) for row in rows]


def execute(query: str, values: tuple = ()) -> None:
    with LOCK, connect() as db:
        try:
            db.execute(query, values)
            db.commit()
        finally:
            if settings.storage_backend != "supabase-postgresql":
                db.close()


def next_ticket_number(db: Any) -> int:
    if settings.storage_backend == "supabase-postgresql":
        db.execute("SELECT pg_advisory_xact_lock(742001)")
        row = db.execute("SELECT COALESCE(MAX(ticket_number), 1000) + 1 AS next_num FROM tickets").fetchone()
        return int(row["next_num"])
    row = db.execute("SELECT COALESCE(MAX(ticket_number), 1000) + 1 AS next_num FROM tickets").fetchone()
    return int(row[0])


def add_timeline(
    db: Any,
    ticket_id: str,
    actor_id: str,
    actor_role: str,
    event_type: str,
    old_status: str | None = None,
    new_status: str | None = None,
    notes: str | None = None,
) -> None:
    db.execute(
        """INSERT INTO ticket_timeline(id,ticket_id,actor_id,actor_role,event_type,old_status,new_status,notes,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (str(uuid.uuid4()), ticket_id, actor_id, actor_role, event_type, old_status, new_status, notes, now()),
    )


def hydrate_ticket(ticket: dict[str, Any]) -> dict[str, Any]:
    ticket = _serialize_row(ticket)
    raw_os = ticket.get("os_info")
    if isinstance(raw_os, dict):
        ticket["os_info"] = raw_os
    else:
        try:
            ticket["os_info"] = json.loads(raw_os or "{}")
        except Exception:
            ticket["os_info"] = {}
    ticket["user_experience_verified"] = bool(ticket.get("user_experience_verified"))
    return ticket
