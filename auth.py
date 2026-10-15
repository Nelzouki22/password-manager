"""Authentication and session security.

* Master passwords are hashed with bcrypt (after a SHA-256 pre-hash so passwords
  longer than bcrypt's 72-byte limit are not silently truncated).
* Accounts lock after repeated failures; a per-IP rate limiter slows spraying.
* The derived vault key lives only in server memory (never in the cookie).
* Session cookies are signed, HttpOnly, SameSite=Strict and expire when idle.
* CSRF tokens protect every state-changing request.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import re
import secrets
import threading
import time
from functools import wraps
from typing import Any, Callable

import bcrypt
from flask import Flask, abort, current_app, flash, g, jsonify, redirect, request, session, url_for

import models
from encryption import Vault, generate_salt
from security_audit import calculate_strength

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_MASTER_LENGTH = 12
MIN_MASTER_SCORE = 3          # "Strong"
MAX_PASSWORD_LENGTH = 1024
BCRYPT_ROUNDS = 12


# ------------------------------------------------------------------ password hashing
def _prehash(password: str) -> bytes:
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_master_password(password: str) -> bytes:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


def verify_master_password(password: str, stored_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), bytes(stored_hash))
    except ValueError:
        return False


_dummy_hash: bytes | None = None


def _get_dummy_hash() -> bytes:
    """A throwaway hash so unknown-user logins cost the same time as real ones."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_master_password(secrets.token_urlsafe(16))
    return _dummy_hash


# ------------------------------------------------------------------- in-memory stores
class VaultKeyStore:
    """Holds derived vault keys server-side, keyed by an unguessable session token.

    Keys expire after an idle period. NOTE: this store is per-process, so run a
    single worker process (several threads are fine) - see the README.
    """

    def __init__(self) -> None:
        self._items: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def put(self, key: bytes, ttl_seconds: float) -> str:
        token = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._items = {t: v for t, v in self._items.items() if v[1] > now}
            self._items[token] = (key, now + ttl_seconds)
        return token

    def get(self, token: str | None, ttl_seconds: float) -> bytes | None:
        if not token:
            return None
        now = time.monotonic()
        with self._lock:
            item = self._items.get(token)
            if item is None or item[1] <= now:
                self._items.pop(token, None)
                return None
            self._items[token] = (item[0], now + ttl_seconds)  # sliding expiry
            return item[0]

    def discard(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._items.pop(token, None)


class RateLimiter:
    """Sliding-window limiter: at most ``limit`` hits per ``window_seconds`` per key."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:
                self._hits.clear()
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def _store() -> VaultKeyStore:
    return current_app.extensions["vault_keys"]


def _idle_seconds() -> int:
    return int(current_app.config["IDLE_TIMEOUT_MINUTES"]) * 60


# ------------------------------------------------------------------------ registration
def validate_registration(username: str, password: str, confirm: str) -> list[str]:
    errors: list[str] = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-32 characters: letters, numbers, dot, dash or underscore.")
    if len(password) < MIN_MASTER_LENGTH:
        errors.append(f"Master password must be at least {MIN_MASTER_LENGTH} characters.")
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors.append("Master password is too long.")
    elif calculate_strength(password).score < MIN_MASTER_SCORE:
        errors.append("Master password is too weak. Try a longer passphrase with mixed characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


def register_user(username: str, password: str, confirm: str) -> tuple[int | None, list[str]]:
    errors = validate_registration(username, password, confirm)
    if errors:
        return None, errors
    try:
        user_id = models.create_user(username, hash_master_password(password), generate_salt())
    except models.UsernameTakenError:
        return None, ["That username is not available."]
    return user_id, []


# ----------------------------------------------------------------------- authentication
def authenticate(username: str, password: str, ip: str | None) -> Any | None:
    """Verify credentials. Returns the user row, or None with a generic failure.

    The caller must show one generic message for every failure so attackers cannot
    tell unknown users, wrong passwords and locked accounts apart.
    """
    cfg = current_app.config
    user = models.get_user_by_username(username) if username else None

    if user is None:
        verify_master_password(password, _get_dummy_hash())
        models.log_event("login_failed", username=username, detail="unknown_user", ip=ip)
        return None

    locked_until = models.parse_iso(user["locked_until"])
    if locked_until and locked_until > models.utcnow():
        verify_master_password(password, _get_dummy_hash())
        models.log_event("login_blocked", user_id=user["id"], username=username, detail="account_locked", ip=ip)
        return None
    if locked_until:  # lock has expired - start fresh
        models.reset_failed_logins(user["id"])

    if not verify_master_password(password, user["password_hash"]):
        locked = models.register_failed_login(user["id"], cfg["MAX_LOGIN_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
        models.log_event("login_failed", user_id=user["id"], username=username, detail="bad_password", ip=ip)
        if locked:
            models.log_event("account_locked", user_id=user["id"], username=username,
                             detail=f"locked_for_{cfg['LOCKOUT_MINUTES']}_minutes", ip=ip)
        return None

    models.record_successful_login(user["id"])
    models.log_event("login_success", user_id=user["id"], username=username, ip=ip)
    return user


def reauthenticate(user: Any, password: str, ip: str | None) -> bool:
    """Re-check the master password before a sensitive action (e.g. export)."""
    cfg = current_app.config
    if verify_master_password(password, user["password_hash"]):
        return True
    locked = models.register_failed_login(user["id"], cfg["MAX_LOGIN_ATTEMPTS"], cfg["LOCKOUT_MINUTES"])
    models.log_event("reauth_failed", user_id=user["id"], username=user["username"], ip=ip)
    if locked:
        models.log_event("account_locked", user_id=user["id"], username=user["username"], ip=ip)
    return False


# ------------------------------------------------------------------------------ sessions
def start_session(user: Any, vault_key: bytes) -> None:
    _store().discard(session.get("vault_token"))
    session.clear()  # new session identity on login
    session["uid"] = user["id"]
    session["uname"] = user["username"]
    session["vault_token"] = _store().put(vault_key, _idle_seconds())
    session.permanent = True


def end_session() -> None:
    _store().discard(session.get("vault_token"))
    session.clear()


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        user_id = session.get("uid")
        key = _store().get(session.get("vault_token"), _idle_seconds()) if user_id else None
        user = models.get_user_by_id(user_id) if key else None
        if user is None:
            session.clear()
            if request.headers.get("X-Requested-With") == "fetch":
                return jsonify(error="Session expired. Please sign in again."), 401
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        g.user = user
        g.vault = Vault(key)
        return view(*args, **kwargs)

    return wrapped


# ------------------------------------------------------------------------------- CSRF
def get_csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def init_csrf(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.before_request
    def _protect_state_changes() -> None:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected = session.get("_csrf")
            supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")
