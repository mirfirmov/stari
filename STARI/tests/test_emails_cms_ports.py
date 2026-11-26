import asyncio

from stari.core.config import make_config
from stari.core.models import HTTPResult
from stari.engines.cms import check_cms
from stari.engines.emails import check_emails
from stari.engines.ports import check_ports


class FakeHTTPClient:
    def __init__(self, pages):
        self.config = make_config("https://example.com")
        self.pages = pages

    async def get(self, url):
        response = self.pages.get(url)
        if response is None:
            return HTTPResult(url, 404, {"content-type": "text/html"}, b"not found")
        return response


def test_email_discovery_collects_visible_and_mailto_addresses_in_scope():
    root = "https://example.com/"
    about = "https://example.com/about"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"},
                         b'<a href="/about">About</a><p>info@example.com</p>'),
        about: HTTPResult(about, 200, {"content-type": "text/html"},
                          b'<a href="mailto:press@example.com">Mail</a>'),
    })
    rows = asyncio.run(check_emails(client, "https://example.com", max_pages=5))
    assert rows[0].evidence["emails"] == ["info@example.com", "press@example.com"]
    assert rows[0].evidence["pages_scanned"][1]["url"] == about


def test_email_discovery_does_not_follow_out_of_scope_links():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"},
                         b'<a href="https://outside.example/contact">Outside</a><p>hello@example.com</p>'),
    })
    rows = asyncio.run(check_emails(client, "https://example.com", max_pages=5))
    assert len(rows[0].evidence["pages_scanned"]) == 1


def test_cms_fingerprints_wordpress_from_public_markers():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html", "server": "nginx"},
                         b'<html><meta name="generator" content="WordPress 6.5"><script src="/wp-content/a.js"></script></html>'),
    })
    rows = asyncio.run(check_cms(client, "https://example.com"))
    detected = rows[0].evidence["detected"]
    assert any(item["name"] == "WordPress" for item in detected)
    assert any(item["name"] == "HTML generator" for item in detected)


def test_ports_checks_only_supplied_web_ports(monkeypatch):
    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def fake_open_connection(host, port):
        assert host == "example.com"
        if port == 443:
            return object(), FakeWriter()
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    rows = asyncio.run(check_ports(
        "example.com", "https://example.com", timeout=0.2,
        requests_per_second=1000, ports=(443, 8080),
    ))
    evidence = rows[0].evidence
    assert evidence["open_ports"] == [443]
    assert [item["port"] for item in evidence["ports"]] == [443, 8080]


def test_ports_refuses_host_not_in_explicit_scope():
    rows = asyncio.run(check_ports(
        "other.example", "https://example.com", timeout=0.2,
        requests_per_second=1000, ports=(443,), allowed_hosts=["example.com"],
    ))
    assert rows[0].check_id == "PORT_SCAN_INVALID_HOST"


def test_cms_detects_wordpress_from_single_strong_resource_path():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"},
                         b'<html><script src="/wp-content/themes/site/app.js"></script></html>'),
    })
    rows = asyncio.run(check_cms(client, root))
    wordpress = next(item for item in rows[0].evidence["detected"] if item["name"] == "WordPress")
    assert wordpress["confidence"] >= 40
    assert wordpress["confidence_level"] in {"MEDIUM", "HIGH"}


def test_cms_does_not_claim_a_cms_from_generic_word_alone():
    root = "https://example.com/"
    client = FakeHTTPClient({
        root: HTTPResult(root, 200, {"content-type": "text/html"},
                         b"<html><body>We use wordpress-inspired design.</body></html>"),
    })
    rows = asyncio.run(check_cms(client, root))
    assert not any(item["name"] == "WordPress" for item in rows[0].evidence["detected"])
