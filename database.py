"""SQLite access layer: per-request connections and automatic schema creation.

Every query in this project is parameterised (``?`` placeholders); user input is
never interpolated into SQL strings.
"""
from __future__ import annotations

import os
import sqlite3

from flask import Flask, current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   BLOB    NOT NULL,              -- bcrypt hash of the master password
    kdf_salt        BLOB    NOT NULL,              -- per-user salt for the vault key (scrypt)
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                          -- UTC ISO-8601, NULL when not locked
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login_at   TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_name  TEXT    NOT NULL,
    username_enc  BLOB    NOT NULL,                -- Fernet token
    password_enc  BLOB    NOT NULL,                -- Fernet token
    website_url   TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username_attempted TEXT,
    event              TEXT NOT NULL,
    detail             TEXT,
    ip_address         TEXT,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, id);
"""


def get_db() -> sqlite3.Connection:
    """Return the request-scoped connection, creating it on first use."""
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(app: Flask) -> None:
    """Create the database directory, file and tables if they do not exist."""
    path = os.path.abspath(app.config["DATABASE_PATH"])
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(path, 0o600)  # owner read/write only
    except OSError:
        pass


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    init_db(app)
