import os
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import base64
import hashlib
import re

import pytest
import requests
from werkzeug.serving import make_server

from seo_agent_connector import ConnectorConfig, SeoAgentConnector, SQLiteArticleRepository
from flask import Flask


@pytest.fixture
def live_connector(tmp_path):
    app = Flask(__name__)
    app.secret_key = "test-secret"
    connector = SeoAgentConnector(ConnectorConfig(
        site_id="test-site", token_db_path=str(tmp_path / "private" / "tokens.sqlite"),
        repository=SQLiteArticleRepository(str(tmp_path / "private" / "articles.sqlite")),
        admin_authorizer=lambda req: req.headers.get("X-Test-Admin") == "yes",
        publish_callback=lambda article: "https://site.test/articles/" + article["slug"],
        require_https=False, rate_limit_per_minute=100,
    )).init_app(app)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", connector
    finally:
        server.shutdown()
        thread.join(timeout=2)


def make_token(base, scopes=("articles:read", "articles:write", "articles:publish")):
    response = requests.post(base + "/admin/seo-agent/tokens", json={"scopes": list(scopes)}, headers={"X-Test-Admin": "yes", "X-Requested-With":"SEOAgentConnector"}, timeout=3)
    assert response.status_code == 201
    return response.json()


def test_token_hash_scope_revocation_and_admin_auth(live_connector):
    base, connector = live_connector
    assert requests.get(base + "/admin/seo-agent", timeout=3).status_code == 403
    created = make_token(base, ("articles:read",))
    with connector._db() as db:
        row = db.execute("SELECT digest FROM tokens WHERE id=?", (created["id"],)).fetchone()
    assert row["digest"] != created["token"]
    headers = {"Authorization": "Bearer " + created["token"]}
    assert requests.get(base + "/api/seo-agent/v1/health", headers=headers, timeout=3).status_code == 200
    assert requests.post(base + "/api/seo-agent/v1/articles", headers=headers, json={}, timeout=3).status_code == 403
    assert requests.post(base + f"/admin/seo-agent/tokens/{created['id']}/revoke", json={}, headers={"X-Test-Admin":"yes", "X-Requested-With":"SEOAgentConnector"}, timeout=3).status_code == 200
    assert requests.get(base + "/api/seo-agent/v1/health", headers=headers, timeout=3).status_code == 401


def test_real_http_article_lifecycle_sanitization_and_idempotency(live_connector):
    base, _ = live_connector
    token = make_token(base)["token"]
    headers = {"Authorization":"Bearer " + token}
    draft = {"external_id":"connect-test-1","title":"Test","slug":"test-page","description":"desc","body_html":"<p>Hi</p><script>alert(1)</script><a href=\"javascript:alert(1)\">bad</a>"}
    first = requests.post(base + "/api/seo-agent/v1/articles", headers=headers, json=draft, timeout=3)
    assert first.status_code == 201 and first.json()["created"] is True
    repeat = requests.post(base + "/api/seo-agent/v1/articles", headers=headers, json=draft, timeout=3)
    assert repeat.status_code == 200 and repeat.json()["created"] is False
    article = requests.get(base + "/api/seo-agent/v1/articles/connect-test-1", headers=headers, timeout=3).json()
    assert "script" not in article["body_html"] and "javascript:" not in article["body_html"]
    update = requests.patch(base + "/api/seo-agent/v1/articles/connect-test-1", headers=headers, json={"title":"Edited"}, timeout=3)
    assert update.status_code == 200 and update.json()["status"] == "draft"
    publish = requests.post(base + "/api/seo-agent/v1/articles/connect-test-1/publish", headers=headers, json={}, timeout=3)
    assert publish.status_code == 200 and publish.json()["published_url"] == "https://site.test/articles/test-page"
    repeat_publish = requests.post(base + "/api/seo-agent/v1/articles/connect-test-1/publish", headers=headers, json={}, timeout=3)
    assert repeat_publish.json()["published_url"] == publish.json()["published_url"]


def test_foreign_data_missing_auth_and_unconfigured_publish(live_connector):
    base, _ = live_connector
    assert requests.get(base + "/api/seo-agent/v1/health", timeout=3).status_code == 401
    token = make_token(base)["token"]
    headers = {"Authorization":"Bearer " + token}
    assert requests.get(base + "/api/seo-agent/v1/articles/unknown", headers=headers, timeout=3).status_code == 404


def test_payload_limit_rate_limit_and_site_isolation(live_connector):
    base, connector = live_connector
    token = make_token(base)["token"]
    headers = {"Authorization":"Bearer " + token}
    oversized = {"external_id":"large-1","title":"Large","slug":"large","body_html":"x" * 1_000_001}
    assert requests.post(base + "/api/seo-agent/v1/articles", headers=headers, json=oversized, timeout=5).status_code == 413
    repo = connector.config.repository
    repo.create_article("site-a", {"external_id":"private-1","title":"A","slug":"a","body_html":"<p>A</p>"})
    assert repo.get_article("site-b", "private-1") is None
    connector.config.rate_limit_per_minute = 1
    with connector._db() as db: db.execute("DELETE FROM usage")
    assert requests.get(base + "/api/seo-agent/v1/health", headers=headers, timeout=3).status_code == 200
    assert requests.get(base + "/api/seo-agent/v1/health", headers=headers, timeout=3).status_code == 429


def test_default_storage_adapter_and_duplicate_initialization(tmp_path):
    app = Flask(__name__, instance_path=str(tmp_path / "instance"))
    app.secret_key = "test-secret"
    repository = SQLiteArticleRepository(str(tmp_path / "existing-articles.sqlite"))

    class Adapter:
        def is_admin(self, request): return request.headers.get("X-Test-Admin") == "yes"
        def create_article(self, site_id, article): return repository.create_article(site_id, article)
        def get_article(self, site_id, external_id): return repository.get_article(site_id, external_id)
        def update_article(self, site_id, external_id, fields): return repository.update_article(site_id, external_id, fields)
        def publish_article(self, site_id, external_id): return repository.publish_article(site_id, external_id)
        def publish(self, article): return "https://site.test/articles/" + article["slug"]

    connector = SeoAgentConnector(adapter=Adapter()).init_app(app)
    connector.init_app(app)
    assert Path(app.instance_path, "seo-agent", "connector.sqlite3").is_file()
    routes = [rule.rule for rule in app.url_map.iter_rules() if rule.rule == "/api/seo-agent/v1/health"]
    assert routes == ["/api/seo-agent/v1/health"]
    with pytest.raises(RuntimeError, match="already initialized"):
        SeoAgentConnector(adapter=Adapter()).init_app(app)


def test_duplicate_publishing_routes_are_rejected(tmp_path):
    app = Flask(__name__)
    app.secret_key = "test-secret"

    @app.get("/api/seo-agent/v1/health")
    def existing_health(): return "existing"

    with pytest.raises(RuntimeError, match="remove the host's duplicate routes"):
        SeoAgentConnector(ConnectorConfig(
            site_id="test-site", token_db_path=str(tmp_path / "private" / "tokens.sqlite"),
            repository=SQLiteArticleRepository(str(tmp_path / "private" / "articles.sqlite")),
        )).init_app(app)


def test_browser_pairing_uses_pkce_and_never_exposes_api_token(tmp_path):
    callback = "https://central.test/seo-agent/pairings/callback"
    app = Flask(__name__)
    app.secret_key = "test-secret"
    connector = SeoAgentConnector(ConnectorConfig(
        site_id="test-site", token_db_path=str(tmp_path / "private" / "tokens.sqlite"),
        repository=SQLiteArticleRepository(str(tmp_path / "private" / "articles.sqlite")),
        admin_authorizer=lambda req: req.headers.get("X-Test-Admin") == "yes",
        require_https=False, oauth_clients={"central": callback},
    )).init_app(app)
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = "state-value-0123456789"
    params = {"client_id":"central", "redirect_uri":callback, "state":state,
              "code_challenge":challenge, "code_challenge_method":"S256", "scope":"articles:read articles:write articles:publish"}
    client = app.test_client()
    headers = {"X-Test-Admin":"yes"}
    consent = client.get("/admin/seo-agent/authorize", query_string=params, headers=headers)
    assert consent.status_code == 200 and "Разрешить подключение".encode() in consent.data
    pending_id = re.search(rb'name="pending_id" value="([^"]+)', consent.data).group(1).decode()
    nonce = re.search(rb'name="nonce" value="([^"]+)', consent.data).group(1).decode()
    approved = client.post("/admin/seo-agent/authorize", data={"pending_id":pending_id, "nonce":nonce, "decision":"approve", **params}, headers=headers)
    query = parse_qs(urlsplit(approved.location).query)
    code = query["code"][0]
    assert query["state"] == [state] and "sac_" not in approved.location
    payload = {"code":code, "client_id":"central", "redirect_uri":callback, "code_verifier":verifier}
    exchanged = client.post("/admin/seo-agent/token", json=payload)
    assert exchanged.status_code == 200
    token = exchanged.json["access_token"]
    assert token.startswith("sac_") and token not in approved.location
    assert client.post("/admin/seo-agent/token", json=payload).status_code == 400
    with connector._db() as db:
        row = db.execute("SELECT digest FROM tokens WHERE site_id=?", ("test-site",)).fetchone()
    assert row["digest"] != token


def test_browser_authorization_denial_and_expired_code(tmp_path):
    callback = "https://central.test/seo-agent/pairings/callback"
    app = Flask(__name__)
    app.secret_key = "test-secret"
    connector = SeoAgentConnector(ConnectorConfig(
        site_id="test-site", token_db_path=str(tmp_path / "private" / "tokens.sqlite"),
        repository=SQLiteArticleRepository(str(tmp_path / "private" / "articles.sqlite")),
        admin_authorizer=lambda req: req.headers.get("X-Test-Admin") == "yes",
        require_https=False, oauth_clients={"central": callback},
    )).init_app(app)
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    params = {"client_id":"central", "redirect_uri":callback, "state":"state-value-0123456789",
              "code_challenge":challenge, "code_challenge_method":"S256", "scope":"articles:read"}
    client = app.test_client()
    consent = client.get("/admin/seo-agent/authorize", query_string=params, headers={"X-Test-Admin":"yes"})
    pending_id = re.search(rb'name="pending_id" value="([^"]+)', consent.data).group(1).decode()
    nonce = re.search(rb'name="nonce" value="([^"]+)', consent.data).group(1).decode()
    denied = client.post("/admin/seo-agent/authorize", data={"pending_id":pending_id, "nonce":nonce,
        "decision":"deny", **params}, headers={"X-Test-Admin":"yes"})
    assert denied.status_code == 303
    assert "access_denied" in denied.location and "state-value-0123456789" in denied.location

    approved = client.get("/admin/seo-agent/authorize", query_string={**params, "state":"state-value-9876543210"}, headers={"X-Test-Admin":"yes"})
    pending_id = re.search(rb'name="pending_id" value="([^"]+)', approved.data).group(1).decode()
    nonce = re.search(rb'name="nonce" value="([^"]+)', approved.data).group(1).decode()
    granted = client.post("/admin/seo-agent/authorize", data={"pending_id":pending_id, "nonce":nonce,
        "decision":"approve", **{**params, "state":"state-value-9876543210"}}, headers={"X-Test-Admin":"yes"})
    code = parse_qs(urlsplit(granted.location).query)["code"][0]
    with connector._db() as db:
        db.execute("UPDATE oauth_codes SET expires_at=0")
    exchange = client.post("/admin/seo-agent/token", json={"code":code, "client_id":"central",
        "redirect_uri":callback, "code_verifier":verifier})
    assert exchange.status_code == 400
