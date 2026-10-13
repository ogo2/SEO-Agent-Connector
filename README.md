# SEO Agent Connector for Flask

Install the released package from the public GitHub repository:

```sh
pip install "vsemodeli-seo-agent-connector @ git+https://github.com/ogo2/SEO-Agent-Connector.git@v1.1.0"
```

For development, omit `@v1.1.0` to install the default branch. Pin a release tag
in production so deployments are reproducible.

## One-time Flask integration

The connector creates its private SQLite metadata store below Flask's
`instance_path` with restrictive file permissions. It does not create a second
article store. Supply a small adapter for the host's administrator login and
existing article/publication service:

```python
from seo_agent_connector import SeoAgentConnector

class SiteAdapter:
    def is_admin(self, request):
        return current_user.is_authenticated and current_user.is_admin

    def create_article(self, site_id, article):
        return existing_articles.create(site_id, article)

    def get_article(self, site_id, external_id):
        return existing_articles.get(site_id, external_id)

    def update_article(self, site_id, external_id, fields):
        return existing_articles.update(site_id, external_id, fields)

    def publish_article(self, site_id, external_id):
        return existing_articles.publish(site_id, external_id)

    def publish(self, article):
        return existing_articles.publish_and_get_https_url(article)

connector = SeoAgentConnector(adapter=SiteAdapter())
connector.init_app(app)
```

The adapter methods operate on the site's existing article system. `publish`
must return the real public HTTPS URL or `None` if publication did not complete.
`publish_article` supplies the repository's internal publish operation. The connector fails closed for admin operations
when no admin authorization adapter is configured.

## Browser authorization

From vsemodeli.pro, enter the site's HTTPS base URL and choose **Connect**. The
browser redirects to the site's admin authorization page. After the site
administrator approves, the connector exchanges a short-lived, single-use
authorization code with vsemodeli.pro using PKCE. The API token travels only
between servers and is never shown or entered in the browser. The default
registered OAuth client is `vsemodeli-pro`; custom deployments can configure
`SEO_AGENT_CONNECTOR_OAUTH_CLIENTS` as an exact map of client IDs to HTTPS
callback URLs.

The existing Publishing API v1 remains at `/api/seo-agent/v1`. Token creation,
scope checks, expiration, revocation, request limits, article validation and
HTML sanitization are handled by the connector. Register it once per Flask app;
initialization rejects existing duplicate Publishing API routes.

## Configuration

Defaults can be overridden in Flask config:

* `SEO_AGENT_CONNECTOR_SITE_ID`: stable connector/site identifier. If omitted,
  it is generated once and persisted in the private connector database.
* `SEO_AGENT_CONNECTOR_STORAGE`: absolute path to the private metadata database.
  If omitted, `instance_path/seo-agent/connector.sqlite3` is used.
* `SEO_AGENT_CONNECTOR_OAUTH_CLIENTS`: exact client-ID to HTTPS callback map.

Keep the Flask instance directory outside the public web root and use HTTPS. If
TLS terminates at a reverse proxy, configure Flask/Werkzeug `ProxyFix` only for
the exact trusted proxy count.
