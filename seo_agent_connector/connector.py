from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import sqlite3
import time
import base64
import uuid
from html import escape
from html.parser import HTMLParser
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit, urlencode

from flask import Blueprint, current_app, g, jsonify, redirect, render_template_string, request, session, abort, send_from_directory

SCOPES = {"articles:read", "articles:write", "articles:publish"}
MAX_BODY = 1_000_000
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ALLOWED_TAGS = {"p", "br", "h1", "h2", "h3", "h4", "ul", "ol", "li", "strong", "b", "em", "i", "blockquote", "a", "code", "pre"}
DROP_TAGS = {"script", "style", "iframe", "object", "embed", "svg", "math", "form"}


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class _SafeArticleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.drop_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP_TAGS:
                self.drop_depth += 1
            return
        if tag in DROP_TAGS:
            self.drop_depth = 1
            return
        if tag not in ALLOWED_TAGS:
            return
        if tag == "br":
            self.parts.append("<br>")
        elif tag == "a":
            href = str(dict(attrs).get("href") or "").strip()
            scheme = urlsplit(href).scheme.lower()
            if href and scheme in {"", "http", "https", "mailto"}:
                self.parts.append(f'<a href="{escape(href, quote=True)}" rel="nofollow noopener">')
            else:
                self.parts.append("<a>")
        else:
            self.parts.append(f"<{tag}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.drop_depth:
            if tag in DROP_TAGS:
                self.drop_depth -= 1
            return
        if tag in ALLOWED_TAGS and tag != "br":
            self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.drop_depth:
            self.parts.append(escape(data))


def _clean_article_html(value: str) -> str:
    parser = _SafeArticleHTML()
    parser.feed(str(value))
    parser.close()
    return "".join(parser.parts)


class ArticleRepository(Protocol):
    def create_article(self, site_id: str, article: dict) -> tuple[dict, bool]: ...
    def get_article(self, site_id: str, external_id: str) -> dict | None: ...
    def update_article(self, site_id: str, external_id: str, fields: dict) -> dict | None: ...
    def publish_article(self, site_id: str, external_id: str) -> dict | None: ...


class HostAdapter(Protocol):
    """Small bridge to the Flask host's admin login and publication system."""
    def is_admin(self, request) -> bool: ...
    def create_article(self, site_id: str, article: dict) -> tuple[dict, bool]: ...
    def get_article(self, site_id: str, external_id: str) -> dict | None: ...
    def update_article(self, site_id: str, external_id: str, fields: dict) -> dict | None: ...
    def publish_article(self, site_id: str, external_id: str) -> dict | None: ...
    def publish(self, article: dict) -> str | None: ...


class SQLiteArticleRepository:
    """Opt-in isolated storage. Use a path outside the web root and protect it as a secret."""
    def __init__(self, path: str):
        if not os.path.isabs(path): raise ValueError("Article storage path must be absolute")
        self.path = os.path.abspath(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._run("CREATE TABLE IF NOT EXISTS articles(site_id TEXT NOT NULL, external_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(site_id,external_id))")
        try: os.chmod(self.path, 0o600)
        except OSError: pass

    def _run(self, sql, args=(), one=False):
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql, args)
            rows = cur.fetchone() if one else cur.fetchall()
            return dict(rows) if one and rows else ([dict(r) for r in rows] if not one else None)

    def create_article(self, site_id, article):
        old = self.get_article(site_id, article["external_id"])
        if old: return self.update_article(site_id, article["external_id"], article), False
        value = {**article, "status": "draft", "published_url": None, "published_at": None, "id": secrets.token_hex(16)}
        self._run("INSERT INTO articles VALUES(?,?,?)", (site_id, article["external_id"], json.dumps(value)))
        return value, True

    def get_article(self, site_id, external_id):
        row = self._run("SELECT data FROM articles WHERE site_id=? AND external_id=?", (site_id, external_id), one=True)
        return json.loads(row["data"]) if row else None

    def update_article(self, site_id, external_id, fields):
        value = self.get_article(site_id, external_id)
        if not value: return None
        value.update(fields)
        self._run("UPDATE articles SET data=? WHERE site_id=? AND external_id=?", (json.dumps(value), site_id, external_id))
        return value

    def publish_article(self, site_id, external_id):
        return self.get_article(site_id, external_id)


@dataclass
class ConnectorConfig:
    site_id: str | None = None
    token_db_path: str | None = None
    admin_authorizer: object | None = None  # callback(request) -> bool; fail-closed when absent
    repository: ArticleRepository | None = None
    public_url_builder: object | None = None  # callback(article) -> public URL; required to claim published
    publish_callback: object | None = None  # callback(article) -> public URL or None
    require_https: bool = True
    rate_limit_per_minute: int = 60
    max_content_length: int = MAX_BODY + 16_384
    oauth_clients: dict[str, str] | None = None


class SeoAgentConnector:
    def __init__(self, config: ConnectorConfig | None = None, *, adapter: HostAdapter | None = None):
        self.config = config or ConnectorConfig()
        self.adapter = adapter

    def init_app(self, app):
        existing = app.extensions.get("seo_agent_connector")
        if existing is self:
            return self
        if existing is not None:
            raise RuntimeError("SeoAgentConnector is already initialized for this Flask app")
        if not app.secret_key:
            raise ValueError("Configure Flask SECRET_KEY before initializing SeoAgentConnector")
        path = self.config.token_db_path or app.config.get("SEO_AGENT_CONNECTOR_STORAGE")
        if not path:
            path = os.path.join(app.instance_path, "seo-agent", "connector.sqlite3")
        if not os.path.isabs(path): raise ValueError("Token storage path must be absolute")
        self.config.token_db_path = os.path.abspath(path)
        public_dir = os.path.realpath(app.static_folder or os.path.join(app.root_path, "static"))
        if os.path.commonpath((public_dir, os.path.realpath(self.config.token_db_path))) == public_dir:
            raise ValueError("Token storage must be outside the public static directory")
        Path(self.config.token_db_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with sqlite3.connect(self.config.token_db_path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS connector_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY, site_id TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, last_used_at TEXT);
                CREATE TABLE IF NOT EXISTS usage(token_id TEXT NOT NULL, at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS oauth_pending(id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT NOT NULL, challenge TEXT NOT NULL, scopes TEXT NOT NULL, nonce_hash TEXT NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS oauth_codes(code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, scopes TEXT NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS admin_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, token_id TEXT, created_at TEXT NOT NULL);
            """)
            token_columns = {row[1] for row in db.execute("PRAGMA table_info(tokens)")}
            if "name" not in token_columns:
                db.execute("ALTER TABLE tokens ADD COLUMN name TEXT NOT NULL DEFAULT 'API token'")
            if "site_id" not in token_columns:
                db.execute("ALTER TABLE tokens ADD COLUMN site_id TEXT NOT NULL DEFAULT ''")
            site_id = self.config.site_id or app.config.get("SEO_AGENT_CONNECTOR_SITE_ID")
            if not site_id:
                stored = db.execute("SELECT value FROM connector_meta WHERE key='site_id'").fetchone()
                site_id = stored[0] if stored else "site_" + uuid.uuid4().hex
            db.execute("INSERT OR REPLACE INTO connector_meta(key,value) VALUES('site_id',?)", (site_id,))
            self.config.site_id = site_id
        try: os.chmod(self.config.token_db_path, 0o600)
        except OSError: pass
        if self.config.repository is None and self.adapter is not None:
            self.config.repository = self.adapter
        if self.config.publish_callback is None and self.adapter is not None:
            self.config.publish_callback = self.adapter.publish
        self.config.admin_authorizer = self.config.admin_authorizer or (self.adapter.is_admin if self.adapter else None)
        if self.config.repository is None:
            raise ValueError("Pass a HostAdapter connected to the site's existing publication system")
        if self.config.oauth_clients is None:
            self.config.oauth_clients = app.config.get("SEO_AGENT_CONNECTOR_OAUTH_CLIENTS") or {
                "vsemodeli-pro": "https://vsemodeli.pro/seo-agent/pairings/callback"
            }
        if not isinstance(self.config.oauth_clients, dict):
            raise ValueError("SEO_AGENT_CONNECTOR_OAUTH_CLIENTS must map client IDs to exact HTTPS redirect URIs")
        app.config.setdefault("MAX_CONTENT_LENGTH", self.config.max_content_length)
        bp = Blueprint("seo_agent_connector_" + re.sub(r"\W", "_", self.config.site_id), __name__)
        self._register(bp)
        required_paths = {"/admin/seo-agent", "/admin/seo-agent/authorize", "/admin/seo-agent/token",
                          "/admin/seo-agent/tokens", "/admin/seo-agent/tokens/<token_id>/revoke",
                          "/api/seo-agent/v1/health", "/api/seo-agent/v1/capabilities",
                          "/api/seo-agent/v1/articles", "/api/seo-agent/v1/articles/<external_id>",
                          "/api/seo-agent/v1/articles/<external_id>/publish"}
        collisions = sorted({rule.rule for rule in app.url_map.iter_rules()} & required_paths)
        if collisions:
            raise RuntimeError("Publishing API v1 routes already exist; remove the host's duplicate routes before registering SeoAgentConnector: " + ", ".join(collisions))
        app.register_blueprint(bp)
        app.extensions["seo_agent_connector"] = self
        app.extensions.setdefault("seo_agent_connectors", {})[self.config.site_id] = self
        return self

    def _db(self):
        db = sqlite3.connect(self.config.token_db_path)
        db.row_factory = sqlite3.Row
        return db

    def _admin(self):
        return bool(self.config.admin_authorizer and self.config.admin_authorizer(request))

    @staticmethod
    def _csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    @staticmethod
    def _admin_post_allowed():
        if request.mimetype != "application/json" or request.headers.get("X-Requested-With") != "SEOAgentConnector":
            return False
        origin = request.headers.get("Origin")
        if not origin:
            return True
        source, target = urlsplit(origin), urlsplit(request.host_url)
        return source.scheme == target.scheme and source.netloc.lower() == target.netloc.lower()

    def _register(self, bp):
        def admin(view):
            @wraps(view)
            def guarded(*a, **kw):
                if not self._admin(): return jsonify(error="Administrative authorization required"), 403
                return view(*a, **kw)
            return guarded

        @bp.get("/admin/seo-agent/assets/<path:filename>")
        def admin_assets(filename):
            if filename not in {"admin.css", "admin.js"}:
                abort(404)
            return send_from_directory(str(Path(__file__).parent / "static"), filename)

        @bp.get("/admin/seo-agent")
        @admin
        def dashboard():
            with self._db() as db:
                rows = db.execute("SELECT id,name,scopes,created_at,expires_at,revoked_at,last_used_at FROM tokens WHERE site_id=? ORDER BY created_at DESC", (self.config.site_id,)).fetchall()
            tokens = [{**dict(r), "scopes": json.loads(r["scopes"])} for r in rows]
            if request.accept_mimetypes.best == "application/json": return jsonify(status="configured", tokens=tokens)
            template = (Path(__file__).parent / "templates" / "admin.html").read_text(encoding="utf-8")
            return render_template_string(template, site=self.config.site_id, base_url=request.url_root.rstrip("/"), version=f"1.1.1 (Python {platform.python_version()})")

        @bp.get("/admin/seo-agent/diagnostics")
        @admin
        def diagnostics():
            checks = [
                {"id": "https", "status": "success" if request.is_secure else "warning", "title": "HTTPS",
                 "detail": "Запрос защищён HTTPS." if request.is_secure else "Откройте панель через HTTPS; настройте TLS на сайте или доверенном reverse proxy."}
            ]
            try:
                with self._db() as db:
                    db.execute("SELECT 1").fetchone()
                import stat
                private_mode = stat.S_IMODE(os.stat(self.config.token_db_path).st_mode) & 0o077 == 0
                storage_ok = private_mode and os.access(self.config.token_db_path, os.R_OK | os.W_OK)
                checks.append({"id": "storage", "status": "success" if storage_ok else "warning", "title": "Хранилище",
                    "detail": "Закрытая SQLite база доступна." if storage_ok else "Проверьте закрытые права файла базы."})
            except (sqlite3.Error, OSError):
                checks.append({"id": "storage", "status": "error", "title": "Хранилище", "detail": "Не удаётся прочитать базу токенов."})
            repo_ok = all(callable(getattr(self.config.repository, method, None)) for method in ("create_article", "get_article", "update_article", "publish_article"))
            checks.extend([
                {"id": "repository", "status": "success" if repo_ok else "error", "title": "Хранилище статей", "detail": "Адаптер статей готов." if repo_ok else "Проверьте адаптер статей."},
                {"id": "auth", "status": "success" if self.config.admin_authorizer else "error", "title": "Авторизация", "detail": "Вход администратора подтверждён callback сайта." if self.config.admin_authorizer else "Задайте callback администратора."},
                {"id": "api", "status": "success" if repo_ok and self.config.admin_authorizer else "warning", "title": "API Publishing v1", "detail": "API v1 доступен при наличии токена." if repo_ok and self.config.admin_authorizer else "Настройте авторизацию и адаптер."},
                {"id": "capabilities", "status": "success" if repo_ok else "error", "title": "Возможности API", "detail": "Черновики и редактирование доступны." if repo_ok else "Проверьте адаптер."},
                {"id": "publish", "status": "success" if self.config.publish_callback else "warning", "title": "Публикация", "detail": "Обработчик публикации настроен." if self.config.publish_callback else "Публикация не настроена. Подключите callback и публичный рендерер."},
            ])
            with self._db() as db:
                last = db.execute("SELECT MAX(last_used_at) FROM tokens WHERE site_id=?", (self.config.site_id,)).fetchone()[0]
            return jsonify(site_id=self.config.site_id, version=f"1.1.1 (Python {platform.python_version()})", api_version=1,
                base_url=request.url_root.rstrip("/"), checks=checks, last_api_at=last)

        def oauth_parameters(values):
            client_id = str(values.get("client_id") or "")
            redirect_uri = str(values.get("redirect_uri") or "")
            if self.config.oauth_clients.get(client_id) != redirect_uri:
                return None
            parts = urlsplit(redirect_uri)
            if parts.scheme != "https" or not parts.netloc or parts.username or parts.password or parts.fragment:
                return None
            state = str(values.get("state") or "")
            challenge = str(values.get("code_challenge") or "")
            if str(values.get("code_challenge_method") or "S256") != "S256":
                return None
            scopes = str(values.get("scope") or "articles:read articles:write articles:publish").split()
            if not (16 <= len(state) <= 256) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
                return None
            if not scopes or set(scopes) - SCOPES:
                return None
            return client_id, redirect_uri, state, challenge, sorted(set(scopes))

        @bp.route("/admin/seo-agent/authorize", methods=["GET", "POST"])
        @admin
        def authorize_client():
            params = oauth_parameters(request.values)
            if not params:
                return jsonify(error="Invalid or unregistered authorization request"), 400
            client_id, redirect_uri, state, challenge, scopes = params
            if request.method == "GET":
                pending_id, nonce = secrets.token_urlsafe(18), secrets.token_urlsafe(32)
                with self._db() as db:
                    db.execute("DELETE FROM oauth_pending WHERE expires_at<?", (time.time(),))
                    db.execute("INSERT INTO oauth_pending VALUES(?,?,?,?,?,?,?,?)", (pending_id, client_id, redirect_uri, state, challenge, json.dumps(scopes), hashlib.sha256(nonce.encode()).hexdigest(), time.time()+600))
                response = current_app.make_response(render_template_string('''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Подключить SEO Agent</title><main style="font:16px system-ui;max-width:600px;margin:3rem auto"><h1>Разрешить подключение?</h1><p>Приложение <b>{{ client|e }}</b> запрашивает доступ к сайту <b>{{ site|e }}</b>.</p><p>Разрешения: {{ scopes|join(', ')|e }}</p><p>Токен будет передан только серверу приложения и не будет показан в браузере.</p><form method="post"><input type="hidden" name="pending_id" value="{{ pending_id|e }}"><input type="hidden" name="nonce" value="{{ nonce|e }}"><input type="hidden" name="_csrf_token" value="{{ csrf|e }}">{% for key,value in params.items() %}<input type="hidden" name="{{ key|e }}" value="{{ value|e }}">{% endfor %}<button name="decision" value="approve">Разрешить</button> <button name="decision" value="deny">Отказать</button></form></main></html>''', client=client_id, site=self.config.site_id, scopes=scopes, pending_id=pending_id, nonce=nonce, csrf=self._csrf_token(), params={"client_id":client_id,"redirect_uri":redirect_uri,"state":state,"code_challenge":challenge,"code_challenge_method":"S256","scope":" ".join(scopes)}))
                response.headers["Cache-Control"] = "no-store"
                response.headers["Referrer-Policy"] = "no-referrer"
                return response
            pending_id, nonce = str(request.form.get("pending_id") or ""), str(request.form.get("nonce") or "")
            csrf = str(request.form.get("_csrf_token") or "")
            expected_csrf = str(session.get("_csrf_token") or "")
            if not csrf or not expected_csrf or not hmac.compare_digest(csrf, expected_csrf):
                return jsonify(error="Invalid CSRF token"), 400
            with self._db() as db:
                row = db.execute("SELECT * FROM oauth_pending WHERE id=?", (pending_id,)).fetchone()
                if not row or row["expires_at"] <= time.time() or not hmac.compare_digest(row["nonce_hash"], hashlib.sha256(nonce.encode()).hexdigest()):
                    return jsonify(error="Authorization request expired"), 400
                db.execute("DELETE FROM oauth_pending WHERE id=?", (pending_id,))
                if request.form.get("decision") != "approve":
                    return redirect(row["redirect_uri"] + "?" + urlencode({"error":"access_denied", "state":row["state"]}), code=303)
                code = secrets.token_urlsafe(32)
                db.execute("INSERT INTO oauth_codes VALUES(?,?,?,?,?,?)", (hashlib.sha256(code.encode()).hexdigest(), row["client_id"], row["redirect_uri"], row["challenge"], row["scopes"], time.time()+120))
            return redirect(row["redirect_uri"] + "?" + urlencode({"code":code, "state":row["state"]}), code=303)

        @bp.post("/admin/seo-agent/token")
        def exchange_code():
            data = request.get_json(silent=True) or {}
            code, client_id, redirect_uri, verifier = (str(data.get(key) or "") for key in ("code", "client_id", "redirect_uri", "code_verifier"))
            if len(code) > 256 or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", verifier):
                return jsonify(error="Invalid authorization code"), 400
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM oauth_codes WHERE code_hash=?", (hashlib.sha256(code.encode()).hexdigest(),)).fetchone()
                if not row or row["expires_at"] <= time.time() or row["client_id"] != client_id or row["redirect_uri"] != redirect_uri or not hmac.compare_digest(row["challenge"], challenge):
                    db.rollback()
                    return jsonify(error="Invalid or expired authorization code"), 400
                db.execute("DELETE FROM oauth_codes WHERE code_hash=?", (row["code_hash"],))
                raw_token = "sac_" + secrets.token_urlsafe(32)
                token_id = secrets.token_urlsafe(12)
                db.execute("INSERT INTO tokens(id,site_id,digest,scopes,created_at,expires_at,revoked_at,last_used_at,name) VALUES(?,?,?,?,?,NULL,NULL,NULL,?)", (token_id, self.config.site_id, hashlib.sha256(raw_token.encode()).hexdigest(), row["scopes"], _now(), client_id))
                db.commit()
            return jsonify(access_token=raw_token, token_type="Bearer", scope=" ".join(json.loads(row["scopes"])), expires_in=None), 200

        @bp.get("/admin/seo-agent/tokens")
        @admin
        def list_tokens():
            with self._db() as db:
                rows = db.execute("SELECT id,name,scopes,created_at,expires_at,revoked_at,last_used_at FROM tokens WHERE site_id=? ORDER BY created_at DESC", (self.config.site_id,)).fetchall()
            return jsonify(tokens=[{**dict(r), "scopes": json.loads(r["scopes"])} for r in rows])

        @bp.post("/admin/seo-agent/tokens")
        @admin
        def create_token():
            if not self._admin_post_allowed(): return jsonify(error="Same-origin JSON request required"), 403
            data = request.get_json(silent=True) or {}
            name = str(data.get("name") or "API token").strip()
            if not name or len(name) > 100: return jsonify(error="Invalid token name"), 400
            scopes = data.get("scopes", [])
            if not isinstance(scopes, list) or not scopes or set(scopes) - SCOPES: return jsonify(error="Invalid scopes"), 400
            expires_at = data.get("expires_at")
            if str(data.get("expires_in")) in {"30", "90", "365"}:
                from datetime import timedelta
                expires_at = (datetime.now(timezone.utc) + timedelta(days=int(data["expires_in"]))).isoformat().replace("+00:00", "Z")
            if expires_at is not None:
                try:
                    expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc): raise ValueError
                    expires_at = expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                except (TypeError, ValueError): return jsonify(error="expires_at must be a future ISO-8601 timestamp with timezone"), 400
            raw = "sac_" + secrets.token_urlsafe(32)
            token_id = secrets.token_urlsafe(12)
            with self._db() as db:
                db.execute("INSERT INTO tokens(id,site_id,digest,scopes,created_at,expires_at,revoked_at,last_used_at,name) VALUES(?,?,?,?,?,?,NULL,NULL,?)", (token_id, self.config.site_id, hashlib.sha256(raw.encode()).hexdigest(), json.dumps(sorted(set(scopes))), _now(), expires_at, name))
                db.execute("INSERT INTO admin_audit(action,token_id,created_at) VALUES(?,?,?)", ("token_created", token_id, _now()))
            return jsonify(id=token_id, name=name, token=raw, scopes=sorted(set(scopes)), created_at=_now(), expires_at=expires_at), 201

        @bp.post("/admin/seo-agent/tokens/<token_id>/revoke")
        @admin
        def revoke_token(token_id):
            if not self._admin_post_allowed(): return jsonify(error="Same-origin JSON request required"), 403
            with self._db() as db:
                cur = db.execute("UPDATE tokens SET revoked_at=? WHERE id=? AND site_id=? AND revoked_at IS NULL", (_now(), token_id, self.config.site_id))
                if cur.rowcount:
                    db.execute("INSERT INTO admin_audit(action,token_id,created_at) VALUES(?,?,?)", ("token_revoked", token_id, _now()))
            return (jsonify(status="revoked"), 200) if cur.rowcount else (jsonify(error="Token not found"), 404)

        def authorized(scope):
            def decorator(view):
                @wraps(view)
                def wrapped(*args, **kwargs):
                    if self.config.require_https and not request.is_secure: return jsonify(error="HTTPS required", error_code="http_400"), 400
                    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
                    if scheme.lower() != "bearer" or not token: return jsonify(error="Authentication required", error_code="http_401"), 401
                    digest = hashlib.sha256(token.encode()).hexdigest()
                    with self._db() as db:
                        row = db.execute("SELECT * FROM tokens WHERE site_id=? AND digest=?", (self.config.site_id, digest)).fetchone()
                        if not row or row["revoked_at"] or (row["expires_at"] and row["expires_at"] <= _now()): return jsonify(error="Authentication required", error_code="http_401"), 401
                        if scope not in json.loads(row["scopes"]): return jsonify(error="Insufficient scope", error_code="http_403"), 403
                        g.seo_agent_scopes = json.loads(row["scopes"])
                        now = time.time()
                        db.execute("DELETE FROM usage WHERE at<?", (now-60,))
                        limit = int(current_app.config.get("SEO_AGENT_API_RATE_LIMIT_PER_MINUTE", self.config.rate_limit_per_minute))
                        if db.execute("SELECT COUNT(*) FROM usage WHERE token_id=?", (row["id"],)).fetchone()[0] >= limit: return jsonify(error="Rate limit exceeded", error_code="http_429"), 429
                        db.execute("INSERT INTO usage VALUES(?,?)", (row["id"], now))
                        db.execute("UPDATE tokens SET last_used_at=? WHERE id=?", (_now(), row["id"]))
                    audit = getattr(self.adapter, "audit_api_request", None)
                    if audit:
                        audit(request, self.config.site_id)
                    return view(*args, **kwargs)
                return wrapped
            return decorator

        repo = self.config.repository
        if repo is None: raise ValueError("Configure an ArticleRepository before init_app")
        @bp.get("/api/seo-agent/v1/health")
        @authorized("articles:read")
        def health(): return jsonify(status="ok", protocol="seo-agent-publishing-api", version=1)

        @bp.get("/api/seo-agent/v1/capabilities")
        @authorized("articles:read")
        def capabilities(): return jsonify(version=1, drafts=True, updates=True, publish=bool(self.config.publish_callback), idempotency="external_id", scopes=g.seo_agent_scopes)

        @bp.app_errorhandler(413)
        def payload_too_large(_error):
            return jsonify(error="Request body too large"), 413

        def parse_article(data, partial=False):
            if not isinstance(data, dict): return None
            allowed = {"external_id", "title", "slug", "description", "body_html"}
            if set(data) - allowed or (not partial and not {"external_id", "title", "slug", "body_html"} <= set(data)): return None
            limits = {"external_id":160,"title":500,"slug":500,"description":2000,"body_html":MAX_BODY}
            for k,v in data.items():
                if not isinstance(v,str) or len(v.encode()) > limits[k]: return None
            if "external_id" in data and not ID_RE.fullmatch(data["external_id"]): return None
            if "title" in data and not data["title"].strip(): return None
            if "slug" in data and not SLUG_RE.fullmatch(data["slug"]): return None
            if "body_html" in data: data["body_html"] = _clean_article_html(data["body_html"])
            return data

        @bp.post("/api/seo-agent/v1/articles")
        @authorized("articles:write")
        def create_article():
            raw = request.get_json(silent=True)
            if isinstance(raw, dict) and isinstance(raw.get("body_html"), str) and len(raw["body_html"].encode()) > MAX_BODY: return jsonify(error="Request body too large"), 413
            data = parse_article(raw)
            if data is None: return jsonify(error="Invalid article"), 400
            value, created = repo.create_article(self.config.site_id, data)
            return jsonify(id=str(value.get("id", data["external_id"])), external_id=data["external_id"], status=value.get("status", "draft"), created=created), 201 if created else 200

        @bp.get("/api/seo-agent/v1/articles/<external_id>")
        @authorized("articles:read")
        def get_article(external_id):
            value = repo.get_article(self.config.site_id, external_id)
            return (jsonify(value), 200) if value else (jsonify(error="Article not found"), 404)

        @bp.patch("/api/seo-agent/v1/articles/<external_id>")
        @authorized("articles:write")
        def update_article(external_id):
            raw = request.get_json(silent=True)
            if isinstance(raw, dict) and isinstance(raw.get("body_html"), str) and len(raw["body_html"].encode()) > MAX_BODY: return jsonify(error="Request body too large"), 413
            data = parse_article(raw, partial=True)
            if data is None: return jsonify(error="Invalid article"), 400
            data.pop("external_id", None)
            value = repo.update_article(self.config.site_id, external_id, data)
            return (jsonify(id=value.get("id", external_id), external_id=external_id, status=value.get("status", "draft")), 200) if value else (jsonify(error="Article not found"), 404)

        @bp.post("/api/seo-agent/v1/articles/<external_id>/publish")
        @authorized("articles:publish")
        def publish_article(external_id):
            value = repo.get_article(self.config.site_id, external_id)
            if not value: return jsonify(error="Article not found"), 404
            if value.get("status") == "published": return jsonify(id=value.get("id", external_id), external_id=external_id, status="published", published_url=value.get("published_url"), published_at=value.get("published_at"))
            if not self.config.publish_callback: return jsonify(error="Public rendering is not configured", status="draft"), 409
            public_url = self.config.publish_callback(value)
            if not public_url or urlsplit(public_url).scheme != "https": return jsonify(error="Publication did not produce a public HTTPS URL", status="draft"), 502
            value = repo.update_article(self.config.site_id, external_id, {"status":"published", "published_url":public_url, "published_at":_now()})
            return jsonify(id=value.get("id", external_id), external_id=external_id, status="published", published_url=public_url, published_at=value["published_at"])
