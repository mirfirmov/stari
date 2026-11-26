import asyncio

from stari.core.config import make_config
from stari.core.models import HTTPResult
from stari.engines.crawler import check_crawler


class FakeHTTPClient:
    def __init__(self, pages):
        self.config = make_config("https://example.com")
        self.pages = pages
        self.calls = []

    async def get(self, url):
        self.calls.append(url)
        return self.pages.get(
            url,
            HTTPResult(url, 404, {"content-type": "text/html"}, b"not found"),
        )


def test_crawler_finds_same_scope_pages_forms_scripts_and_api_routes():
    root = "https://example.com/"
    about = "https://example.com/about"
    script = "https://example.com/assets/app.js"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"}, b'''<html><title>Home</title>
            <a href="/about">About</a><a href="https://outside.example/secret">External</a>
            <a href="/api/v1/items?limit=5">API</a>
            <form action="/search" method="POST"><input name="q"></form>
            <script src="/assets/app.js"></script></html>'''),
        about: HTTPResult(about, 200, {"content-type": "text/html"}, b"<title>About</title>"),
        script: HTTPResult(script, 200, {"content-type": "application/javascript"}, b'''fetch("/api/v2/users");
            const endpoint = "https://outside.example/api/private";'''),
    })
    rows = asyncio.run(check_crawler(client, root, max_pages=20, max_scripts=10))
    evidence = rows[0].evidence
    assert {item["url"] for item in evidence["pages_visited"]} >= {root, about}
    assert evidence["forms"][0]["method"] == "POST"
    assert evidence["forms"][0]["field_names"] == ["q"]
    assert evidence["forms_submitted"] is False
    assert script in evidence["scripts"]
    assert any("/api/v1/items" in item for item in evidence["api_endpoints"])
    assert any("/api/v2/users" in item for item in evidence["api_endpoints"])
    assert all("outside.example" not in call for call in client.calls)


def test_crawler_does_not_follow_sensitive_query_or_state_changing_paths():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"}, b'''
            <a href="/profile?token=secret-value">Profile</a>
            <a href="/logout">Logout</a><a href="/safe?page=2">Safe</a>
        '''),
        "https://example.com/safe?page=2": HTTPResult(
            "https://example.com/safe?page=2", 200, {"content-type": "text/html"}, b"ok"
        ),
    })
    rows = asyncio.run(check_crawler(client, root, max_pages=10))
    joined = " ".join(client.calls)
    assert "token=secret-value" not in joined
    assert "/logout" not in joined
    assert "https://example.com/safe?page=2" in client.calls
    assert "sensitive_query_values_stored" in rows[0].evidence


def test_crawler_caps_pages_and_scripts():
    root = "https://example.com/"
    client = FakeHTTPClient({root: HTTPResult(root, 200, {"content-type": "text/html"}, b"ok")})
    rows = asyncio.run(check_crawler(client, root, max_pages=10000, max_scripts=10000))
    assert rows[0].evidence["max_pages"] == 500
    assert rows[0].evidence["max_scripts"] == 100


def test_crawler_skips_state_changing_query_actions():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"}, b"""
            <a href="/?action=delete">Delete</a>
            <a href="/?do=logout">Logout</a>
            <a href="/safe?action=view">Safe</a>
        """),
        "https://example.com/safe?action=view": HTTPResult(
            "https://example.com/safe?action=view", 200, {"content-type": "text/html"}, b"ok"
        ),
    })
    asyncio.run(check_crawler(client, root, max_pages=10))
    assert all("action=delete" not in call and "do=logout" not in call for call in client.calls)
    assert "https://example.com/safe?action=view" in client.calls
