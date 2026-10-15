"""Data-access functions for users, credentials and audit logs.

Every credential query is scoped by ``user_id`` so one user can never read or
modify another user's rows (protection against IDOR).
"""
from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from database import get_db

_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
audit_logger = logging.getLogger("pwm.audit")


class UsernameTakenError(Exception):
    """Raised when registering a username that already exists."""


# --------------------------------------------------------------------------- time
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(_TS_FORMAT)


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _TS_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# -------------------------------------------------------------------------- users
def create_user(username: str, password_hash: bytes, kdf_salt: bytes) -> int:
    db = get_db()
    try:
        with db:
            cur = db.execute(
                "INSERT INTO users (username, password_hash, kdf_salt) VALUES (?, ?, ?)",
                (username, password_hash, kdf_salt),
            )
    except sqlite3.IntegrityError as exc:
        raise UsernameTakenError(username) from exc
    return int(cur.lastrowid)


def get_user_by_username(username: str) -> sqlite3.Row | None:
    # The column uses COLLATE NOCASE, so this lookup is case-insensitive.
    return get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def register_failed_login(user_id: int, max_attempts: int, lock_minutes: int) -> bool:
    """Count a failed login atomically; lock the account at the threshold.

    Returns True when the account is now locked.
    """
    locked_until = to_iso(utcnow() + timedelta(minutes=lock_minutes))
    db = get_db()
    with db:
        db.execute(
            """UPDATE users
                  SET failed_attempts = failed_attempts + 1,
                      locked_until = CASE WHEN failed_attempts + 1 >= ? THEN ? ELSE locked_until END
                WHERE id = ?""",
            (max_attempts, locked_until, user_id),
        )
    row = db.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row and row["failed_attempts"] >= max_attempts)


def reset_failed_logins(user_id: int) -> None:
    db = get_db()
    with db:
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))


def record_successful_login(user_id: int) -> None:
    db = get_db()
    with db:
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
            (to_iso(utcnow()), user_id),
        )


# ---------------------------------------------------------------------- credentials
def create_credential(
    user_id: int,
    account_name: str,
    username_enc: bytes,
    password_enc: bytes,
    website_url: str,
    created_at: str | None = None,
) -> int:
    now = to_iso(utcnow())
    created = created_at or now
    db = get_db()
    with db:
        cur = db.execute(
            """INSERT INTO credentials
                   (user_id, account_name, username_enc, password_enc, website_url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, account_name, username_enc, password_enc, website_url, created, now),
        )
    return int(cur.lastrowid)


def get_credential(user_id: int, credential_id: int) -> sqlite3.Row | None:
    return get_db().execute(
        "SELECT * FROM credentials WHERE id = ? AND user_id = ?", (credential_id, user_id)
    ).fetchone()


def list_credentials(user_id: int) -> list[sqlite3.Row]:
    return get_db().execute(
        "SELECT * FROM credentials WHERE user_id = ? ORDER BY account_name COLLATE NOCASE, id",
        (user_id,),
    ).fetchall()


def update_credential(
    user_id: int,
    credential_id: int,
    account_name: str,
    username_enc: bytes,
    password_enc: bytes | None,
    website_url: str,
) -> bool:
    """Update a credential. ``password_enc=None`` keeps the stored password."""
    now = to_iso(utcnow())
    db = get_db()
    with db:
        if password_enc is None:
            cur = db.execute(
                """UPDATE credentials
                      SET account_name = ?, username_enc = ?, website_url = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?""",
                (account_name, username_enc, website_url, now, credential_id, user_id),
            )
        else:
            cur = db.execute(
                """UPDATE credentials
                      SET account_name = ?, username_enc = ?, password_enc = ?, website_url = ?, updated_at = ?
                    WHERE id = ? AND user_id = ?""",
                (account_name, username_enc, password_enc, website_url, now, credential_id, user_id),
            )
    return cur.rowcount > 0


def delete_credential(user_id: int, credential_id: int) -> bool:
    db = get_db()
    with db:
        cur = db.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?", (credential_id, user_id))
    return cur.rowcount > 0


# ------------------------------------------------------------------------ audit log
def _clean(value: Any, limit: int = 200) -> str | None:
    """Make a value safe for logs: printable ASCII only (blocks log injection), truncated."""
    if value is None:
        return None
    return re.sub(r"[^\x20-\x7E]", "?", str(value))[:limit]


def log_event(
    event: str,
    *,
    user_id: int | None = None,
    username: str | None = None,
    detail: str | None = None,
    ip: str | None = None,
) -> None:
    """Record a security event in the database and the audit log file.

    Never pass passwords, usernames of stored credentials or other secrets here.
    """
    event, username, detail, ip = _clean(event, 64), _clean(username, 64), _clean(detail), _clean(ip, 64)
    db = get_db()
    with db:
        db.execute(
            """INSERT INTO audit_logs (user_id, username_attempted, event, detail, ip_address)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, username, event, detail, ip),
        )
    audit_logger.info(
        "event=%s user_id=%s username=%s ip=%s detail=%s", event, user_id, username, ip, detail
    )


def list_audit_logs(user_id: int, limit: int = 100) -> list[sqlite3.Row]:
    return get_db().execute(
        "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()
