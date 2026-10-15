"""Flask application: routes, configuration and security headers.

Run (development):   flask --app app run        or      python app.py
Run (production):    gunicorn --workers 1 --threads 4 "app:create_app()"
"""
from __future__ import annotations

import io
import logging
import os
import re
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

import auth
import database
import models
from auth import login_required
from encryption import DecryptionError, decrypt_backup, derive_vault_key, encrypt_backup
from password_generator import MAX_LENGTH, MIN_LENGTH, generate_password
from security_audit import audit_vault, calculate_strength

MAX_BACKUP_ITEMS = 5000
SEARCH_FIELDS = {"all", "website", "username", "account"}
MIN_BACKUP_PASSPHRASE = 12


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
        ENCRYPTION_PEPPER=os.environ.get("ENCRYPTION_PEPPER", ""),
        DATABASE_PATH=os.environ.get("DATABASE_PATH") or os.path.join(app.instance_path, "vault.db"),
        LOG_DIR=os.environ.get("LOG_DIR", "logs"),
        IDLE_TIMEOUT_MINUTES=int(os.environ.get("SESSION_IDLE_MINUTES", "15")),
        MAX_LOGIN_ATTEMPTS=int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5")),
        LOCKOUT_MINUTES=int(os.environ.get("LOCKOUT_MINUTES", "15")),
        SESSION_COOKIE_NAME="pwm_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", False),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        TRUST_PROXY=_env_bool("TRUST_PROXY", False),
        LOGIN_RATE_LIMIT=20,        # attempts per IP per 10 minutes
        REGISTER_RATE_LIMIT=10,     # sign-ups per IP per hour
    )
    if test_config:
        app.config.update(test_config)

    for name in ("SECRET_KEY", "ENCRYPTION_PEPPER"):
        if len(app.config[name]) < 32:
            raise RuntimeError(
                f"{name} must be set (at least 32 characters) in the environment or .env file. "
                'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=app.config["IDLE_TIMEOUT_MINUTES"])

    if app.config["TRUST_PROXY"]:  # only enable behind a reverse proxy you control
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # type: ignore[method-assign]

    database.init_app(app)
    app.extensions["vault_keys"] = auth.VaultKeyStore()
    app.extensions["login_limiter"] = auth.RateLimiter(app.config["LOGIN_RATE_LIMIT"], 600)
    app.extensions["register_limiter"] = auth.RateLimiter(app.config["REGISTER_RATE_LIMIT"], 3600)
    auth.init_csrf(app)
    _configure_audit_file_log(app)
    _register_hooks(app)
    _register_routes(app)
    _register_error_handlers(app)
    return app


# ============================================================================ plumbing
def _configure_audit_file_log(app: Flask) -> None:
    logger = logging.getLogger("pwm.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return
    try:
        os.makedirs(app.config["LOG_DIR"], mode=0o700, exist_ok=True)
        handler = RotatingFileHandler(
            os.path.join(app.config["LOG_DIR"], "audit.log"), maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())


def _register_hooks(app: Flask) -> None:
    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"  # never cache pages that may show secrets
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.template_filter("datefmt")
    def datefmt(value: str | None, fmt: str = "%b %d, %Y") -> str:
        moment = models.parse_iso(value)
        return moment.strftime(fmt) if moment else "-"


def _register_error_handlers(app: Flask) -> None:
    def respond(error: Any, title: str):
        message = getattr(error, "description", None) or title
        if request.headers.get("X-Requested-With") == "fetch":
            return jsonify(error=message), error.code
        return render_template("error.html", code=error.code, title=title, message=message), error.code

    @app.errorhandler(400)
    def bad_request(e): return respond(e, "Bad request")

    @app.errorhandler(404)
    def not_found(e): return respond(e, "Page not found")

    @app.errorhandler(413)
    def too_large(e): return respond(e, "File too large")

    @app.errorhandler(429)
    def too_many(e): return respond(e, "Too many requests")

    @app.errorhandler(500)
    def server_error(e):
        e.description = "Something went wrong on our side."  # never leak internals
        return respond(e, "Server error")


# ================================================================== helpers (private)
def _ip() -> str | None:
    return request.remote_addr


def _log(event: str, detail: str | None = None) -> None:
    models.log_event(event, user_id=g.user["id"], username=g.user["username"], detail=detail, ip=_ip())


def _decrypt_entries() -> tuple[list[dict[str, Any]], int]:
    """Decrypt the signed-in user's whole vault in memory. Returns (entries, unreadable_count)."""
    entries, unreadable = [], 0
    for row in models.list_credentials(g.user["id"]):
        try:
            entries.append({
                "id": row["id"],
                "account_name": row["account_name"],
                "username": g.vault.decrypt(row["username_enc"]),
                "password": g.vault.decrypt(row["password_enc"]),
                "website_url": row["website_url"] or "",
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        except DecryptionError:
            unreadable += 1
    return entries, unreadable


def _normalize_url(raw: str) -> tuple[str, str | None]:
    """Accept only well-formed http(s) URLs (blocks javascript:, data:, etc.)."""
    raw = raw.strip()
    if not raw:
        return "", None
    error = "Website must be a valid http(s) URL."
    if len(raw) > 2048 or re.search(r"[\s\x00-\x1f\x7f]", raw):
        return "", error
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        host, _port = parsed.hostname, parsed.port   # .port raises ValueError if malformed
    except ValueError:
        return "", error
    valid_host = bool(host) and (
        re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", host) is not None
        or re.fullmatch(r"[0-9A-Fa-f:.]+", host) is not None          # IPv6 literal
    )
    if parsed.scheme not in {"http", "https"} or not valid_host:
        return "", error
    return raw, None


def _clean_credential_form(form: Any, *, require_password: bool) -> tuple[dict[str, str], list[str]]:
    data = {
        "account_name": form.get("account_name", "").strip(),
        "username": form.get("username", "").strip(),
        "password": form.get("password", ""),
    }
    errors: list[str] = []
    if not data["account_name"] or len(data["account_name"]) > 100:
        errors.append("Account name is required (max 100 characters).")
    if not data["username"] or len(data["username"]) > 200:
        errors.append("Username is required (max 200 characters).")
    if require_password and not data["password"]:
        errors.append("Password is required.")
    if len(data["password"]) > auth.MAX_PASSWORD_LENGTH:
        errors.append("Password is too long.")
    data["website_url"], url_error = _normalize_url(form.get("website_url", ""))
    if url_error:
        errors.append(url_error)
    return data, errors


def _flash_password_warnings(password: str, entries: list[dict[str, Any]], exclude_id: int | None = None) -> None:
    strength = calculate_strength(password)
    if strength.is_weak:
        flash(f"Warning: this password is {strength.label.lower()}. Consider generating a stronger one.", "warning")
    reused = [e["account_name"] for e in entries if e["password"] == password and e["id"] != exclude_id]
    if reused:
        flash("Warning: this password is already used for: " + ", ".join(reused[:5]) + ".", "warning")


# ====================================================================== routes
def _register_routes(app: Flask) -> None:
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if session.get("uid") else "login"))

    # ---------------------------------------------------------------- accounts
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            if not app.extensions["register_limiter"].allow(_ip() or "?"):
                abort(429, description="Too many sign-ups from this address. Try again later.")
            username = request.form.get("username", "").strip()
            user_id, errors = auth.register_user(
                username, request.form.get("password", ""), request.form.get("confirm_password", "")
            )
            if errors:
                for message in errors:
                    flash(message, "danger")
                return render_template("register.html", username=username), 400
            models.log_event("user_registered", user_id=user_id, username=username, ip=_ip())
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", username="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if not app.extensions["login_limiter"].allow(_ip() or "?"):
                models.log_event("login_rate_limited", ip=_ip())
                abort(429, description="Too many sign-in attempts. Please wait a few minutes.")
            username = request.form.get("username", "").strip()[:64]
            password = request.form.get("password", "")[: auth.MAX_PASSWORD_LENGTH]
            user = auth.authenticate(username, password, _ip())
            if user is None:
                flash("Invalid credentials, or the account is temporarily locked.", "danger")
                return render_template("login.html", username=username), 401
            key = derive_vault_key(password, user["kdf_salt"], app.config["ENCRYPTION_PEPPER"])
            auth.start_session(user, key)
            return redirect(url_for("dashboard"))
        if session.get("uid"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", username="")

    @app.post("/logout")
    def logout():
        if session.get("uid"):
            models.log_event("logout", user_id=session["uid"], username=session.get("uname"), ip=_ip())
        auth.end_session()
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    # --------------------------------------------------------------- dashboard
    @app.get("/dashboard")
    @login_required
    def dashboard():
        entries, unreadable = _decrypt_entries()
        report = audit_vault(entries)
        recent = sorted(entries, key=lambda e: e["created_at"], reverse=True)[:5]
        recent = [{k: v for k, v in e.items() if k != "password"} for e in recent]
        if unreadable:
            flash(f"{unreadable} entr{'y' if unreadable == 1 else 'ies'} could not be decrypted.", "danger")
        return render_template("dashboard.html", report=report, recent=recent)

    # ------------------------------------------------------------------- vault
    @app.get("/vault")
    @login_required
    def vault():
        query = request.args.get("q", "").strip()[:100]
        field = request.args.get("field", "all")
        field = field if field in SEARCH_FIELDS else "all"
        entries, _ = _decrypt_entries()
        report = audit_vault(entries)

        def matches(entry: dict[str, Any]) -> bool:
            needle = query.casefold()
            haystacks = {
                "website": [entry["website_url"]],
                "username": [entry["username"]],
                "account": [entry["account_name"]],
            }
            fields = haystacks.values() if field == "all" else [haystacks[field]]
            return any(needle in value.casefold() for values in fields for value in values)

        rows = []
        for entry in entries:
            if query and not matches(entry):
                continue
            row = {k: v for k, v in entry.items() if k != "password"}  # never send passwords to templates
            row["strength"] = report["strengths"][entry["id"]]
            rows.append(row)
        return render_template("vault.html", rows=rows, query=query, field=field, total=len(entries))

    @app.route("/credentials/new", methods=["GET", "POST"])
    @login_required
    def credential_new():
        form = {"account_name": "", "username": "", "website_url": ""}
        if request.method == "POST":
            data, errors = _clean_credential_form(request.form, require_password=True)
            form = {k: data[k] for k in form}
            if errors:
                for message in errors:
                    flash(message, "danger")
                return render_template("credential_form.html", form=form, editing=False, limits=_limits()), 400
            entries, _ = _decrypt_entries()
            new_id = models.create_credential(
                g.user["id"], data["account_name"], g.vault.encrypt(data["username"]),
                g.vault.encrypt(data["password"]), data["website_url"],
            )
            _log("password_created", f"id={new_id} account={data['account_name']}")
            flash("Password saved.", "success")
            _flash_password_warnings(data["password"], entries)
            return redirect(url_for("vault"))
        return render_template("credential_form.html", form=form, editing=False, limits=_limits())

    @app.route("/credentials/<int:credential_id>/edit", methods=["GET", "POST"])
    @login_required
    def credential_edit(credential_id: int):
        row = models.get_credential(g.user["id"], credential_id)
        if row is None:
            abort(404)
        try:
            current_username = g.vault.decrypt(row["username_enc"])
        except DecryptionError:
            abort(500)
        form = {"account_name": row["account_name"], "username": current_username,
                "website_url": row["website_url"] or ""}
        if request.method == "POST":
            data, errors = _clean_credential_form(request.form, require_password=False)
            form = {k: data[k] for k in form}
            if errors:
                for message in errors:
                    flash(message, "danger")
                return render_template("credential_form.html", form=form, editing=True,
                                       credential_id=credential_id, limits=_limits()), 400
            new_password = data["password"] or None
            entries, _ = _decrypt_entries() if new_password else ([], 0)
            models.update_credential(
                g.user["id"], credential_id, data["account_name"], g.vault.encrypt(data["username"]),
                g.vault.encrypt(new_password) if new_password else None, data["website_url"],
            )
            _log("password_updated" if new_password else "credential_edited",
                 f"id={credential_id} account={data['account_name']}")
            flash("Entry updated.", "success")
            if new_password:
                _flash_password_warnings(new_password, entries, exclude_id=credential_id)
            return redirect(url_for("vault"))
        return render_template("credential_form.html", form=form, editing=True,
                               credential_id=credential_id, limits=_limits())

    @app.post("/credentials/<int:credential_id>/delete")
    @login_required
    def credential_delete(credential_id: int):
        row = models.get_credential(g.user["id"], credential_id)
        if row is None:
            abort(404)
        models.delete_credential(g.user["id"], credential_id)
        _log("password_deleted", f"id={credential_id} account={row['account_name']}")
        flash("Entry deleted.", "info")
        return redirect(url_for("vault"))

    @app.post("/credentials/<int:credential_id>/reveal")
    @login_required
    def credential_reveal(credential_id: int):
        row = models.get_credential(g.user["id"], credential_id)
        if row is None:
            abort(404)
        try:
            password = g.vault.decrypt(row["password_enc"])
        except DecryptionError:
            abort(500)
        _log("password_revealed", f"id={credential_id}")
        return jsonify(password=password)

    # --------------------------------------------------------------------- API
    @app.get("/api/generate")
    @login_required
    def api_generate():
        def flag(name: str, default: bool = True) -> bool:
            return request.args.get(name, "1" if default else "0") in {"1", "true", "on"}

        try:
            password = generate_password(
                int(request.args.get("length", 20)),
                use_upper=flag("upper"), use_lower=flag("lower"),
                use_digits=flag("digits"), use_symbols=flag("symbols"),
                exclude_ambiguous=flag("ambiguous", False),
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(password=password, strength=calculate_strength(password).as_dict())

    @app.post("/api/strength")
    @login_required
    def api_strength():
        payload = request.get_json(silent=True) or {}
        password = payload.get("password", "")
        if not isinstance(password, str) or len(password) > auth.MAX_PASSWORD_LENGTH:
            return jsonify(error="Invalid password."), 400
        return jsonify(calculate_strength(password).as_dict())

    # ------------------------------------------------------------------- audit
    @app.get("/audit")
    @login_required
    def audit_page():
        entries, _ = _decrypt_entries()
        report = audit_vault(entries)
        logs = models.list_audit_logs(g.user["id"], 100)
        return render_template("audit.html", report=report, logs=logs)

    # ----------------------------------------------------------------- backups
    @app.get("/backup")
    @login_required
    def backup_page():
        return render_template("backup.html", min_passphrase=MIN_BACKUP_PASSPHRASE)

    @app.post("/backup/export")
    @login_required
    def backup_export():
        passphrase = request.form.get("passphrase", "")
        if len(passphrase) < MIN_BACKUP_PASSPHRASE or passphrase != request.form.get("confirm_passphrase", ""):
            flash(f"Backup passphrase must match and be at least {MIN_BACKUP_PASSPHRASE} characters.", "danger")
            return redirect(url_for("backup_page"))
        if not auth.reauthenticate(g.user, request.form.get("master_password", ""), _ip()):
            flash("Master password incorrect.", "danger")
            return redirect(url_for("backup_page"))
        entries, _ = _decrypt_entries()
        payload = {
            "exported_at": models.to_iso(models.utcnow()),
            "credentials": [{k: e[k] for k in ("account_name", "username", "password", "website_url", "created_at")}
                            for e in entries],
        }
        blob = encrypt_backup(payload, passphrase)
        _log("backup_exported", f"count={len(entries)}")
        name = f"vault-backup-{datetime.now():%Y%m%d-%H%M%S}.pwmbackup"
        return send_file(io.BytesIO(blob), mimetype="application/octet-stream", as_attachment=True, download_name=name)

    @app.post("/backup/import")
    @login_required
    def backup_import():
        upload = request.files.get("backup_file")
        if upload is None or not upload.filename:
            flash("Choose a backup file to import.", "danger")
            return redirect(url_for("backup_page"))
        try:
            payload = decrypt_backup(upload.read(), request.form.get("passphrase", ""))
        except DecryptionError:
            _log("backup_import_failed")
            flash("Could not decrypt the backup. Check the passphrase and that the file is unmodified.", "danger")
            return redirect(url_for("backup_page"))

        items = payload.get("credentials")
        if not isinstance(items, list) or len(items) > MAX_BACKUP_ITEMS:
            flash("Backup contents are invalid.", "danger")
            return redirect(url_for("backup_page"))

        imported = skipped = 0
        for item in items:
            if not isinstance(item, dict):
                skipped += 1
                continue
            account, username, password = (item.get(k) for k in ("account_name", "username", "password"))
            valid = (isinstance(account, str) and 0 < len(account.strip()) <= 100
                     and isinstance(username, str) and 0 < len(username.strip()) <= 200
                     and isinstance(password, str) and 0 < len(password) <= auth.MAX_PASSWORD_LENGTH)
            if not valid:
                skipped += 1
                continue
            raw_url = item.get("website_url") or ""
            url, url_error = _normalize_url(raw_url) if isinstance(raw_url, str) else ("", "invalid")
            created = item.get("created_at")
            models.create_credential(
                g.user["id"], account.strip(), g.vault.encrypt(username.strip()), g.vault.encrypt(password),
                "" if url_error else url, created if isinstance(created, str) and models.parse_iso(created) else None,
            )
            imported += 1
        _log("backup_imported", f"imported={imported} skipped={skipped}")
        flash(f"Imported {imported} entr{'y' if imported == 1 else 'ies'}"
              + (f", skipped {skipped} invalid." if skipped else "."), "success")
        return redirect(url_for("vault"))


def _limits() -> dict[str, int]:
    return {"min": MIN_LENGTH, "max": MAX_LENGTH}


if __name__ == "__main__":
    create_app().run(debug=_env_bool("FLASK_DEBUG", False))
