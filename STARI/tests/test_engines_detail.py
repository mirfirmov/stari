import asyncio

from stari.core.config import make_config
from stari.core.models import HTTPResult, Observation
from stari.engines.headers import check_headers
from stari.engines.sitemap import check_sitemap
from stari.ui import render_scan_details


class FakeHTTPClient:
    def __init__(self, response):
        self.response = response
        self.config = make_config("https://example.com")

    async def get(self, _url):
        return self.response


def test_headers_keep_public_values_and_redact_cookie_values():
    response = HTTPResult(
        url="https://example.com/",
        status_code=200,
        headers={
            "server": "nginx",
            "content-type": "text/html",
            "set-cookie": "session=secret-token; HttpOnly",
        },
        body=b"<html></html>",
        header_items=[
            ("server", "nginx"),
            ("content-type", "text/html"),
            ("set-cookie", "session=secret-token; HttpOnly"),
        ],
    )
    observations = asyncio.run(check_headers(FakeHTTPClient(response), "https://example.com"))
    root = observations[0]
    assert root.evidence["http_status"] == 200
    assert {item["name"] for item in root.evidence["response_headers"]} == {
        "server", "content-type", "set-cookie"
    }
    cookie_header = next(item["value"] for item in root.evidence["response_headers"] if item["name"] == "set-cookie")
    assert "secret-token" not in cookie_header
    assert "session=<redacted>" in cookie_header
    assert any(item.check_id == "COOKIE_ATTRIBUTES_REVIEW" for item in observations)


def test_sitemap_check_returns_full_in_scope_url_list():
    xml = b'''<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/</loc></url>
      <url><loc>https://example.com/about</loc></url>
      <url><loc>https://outside.example.net/private</loc></url>
    </urlset>'''
    response = HTTPResult(
        url="https://example.com/sitemap.xml", status_code=200,
        headers={"content-type": "application/xml"}, body=xml,
    )
    observations = asyncio.run(check_sitemap(FakeHTTPClient(response), "https://example.com"))
    evidence = observations[0].evidence
    assert evidence["locations"] == ["https://example.com/", "https://example.com/about"]
    assert evidence["ignored_out_of_scope"] == 1


def test_dns_rendering_prints_values(monkeypatch):
    from io import StringIO
    from rich.console import Console
    import stari.ui as ui

    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, force_terminal=False, color_system=None))
    rows = [Observation(
        "DNS_A_RECORDS", "DNS A records", "INFO", "OBSERVED", "https://example.com",
        "2 A records", {"record_type": "A", "records": ["192.0.2.10", "192.0.2.11"],
                        "ttl_seconds": 300, "canonical_name": "example.com."},
    )]
    render_scan_details("dns", rows)
    printed = output.getvalue()
    assert "192.0.2.10" in printed
    assert "192.0.2.11" in printed
    assert "300" in printed


def test_rendering_displays_sitemap_urls_and_http_headers(monkeypatch):
    from io import StringIO
    from rich.console import Console
    import stari.ui as ui

    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, force_terminal=False, color_system=None))
    sitemap_rows = [Observation(
        "SITEMAP_ANALYZED", "sitemap.xml analyzed", "INFO", "OBSERVED",
        "https://example.com/sitemap.xml", "Collected 1 URL", 
        {"locations": ["https://example.com/about"]},
    )]
    headers_rows = [Observation(
        "HTTP_ROOT_RESPONSE", "Root response", "INFO", "OBSERVED", "https://example.com",
        "HTTP 200", {"http_status": 200, "final_url": "https://example.com/",
                     "response_headers": [{"name": "server", "value": "test-server"}]},
    )]
    render_scan_details("sitemap", sitemap_rows)
    render_scan_details("headers", headers_rows)
    printed = output.getvalue()
    assert "https://example.com/about" in printed
    assert "test-server" in printed


def test_whois_details_render_domain_fields_and_dns_ip_note(monkeypatch):
    from io import StringIO
    from rich.console import Console

    from stari import ui

    output = StringIO()
    fake_console = Console(file=output, force_terminal=False, color_system=None)
    monkeypatch.setattr(ui, "console", fake_console)
    ui.render_scan_details("whois", [
        {
            "id": 1,
            "check_id": "WHOIS_SERVER_IP_ADDRESSES",
            "evidence": {"addresses": ["8.8.8.8"]},
            "target": "https://example.com",
        },
        {
            "id": 2,
            "check_id": "WHOIS_DOMAIN_REGISTRATION",
            "evidence": {
                "lookup_type": "domain",
                "query": "example.com",
                "source": "RDAP",
                "fields": {"domain_name": "EXAMPLE.COM", "registrar": "Example Registrar"},
            },
            "target": "https://example.com",
        },
        {
            "id": 3,
            "check_id": "WHOIS_IP_REGISTRATION",
            "evidence": {
                "lookup_type": "ip",
                "query": "8.8.8.8",
                "source": "WHOIS",
                "fields": {"cidr": ["8.8.8.0/24"], "net_name": ["PUBLIC-DNS"]},
            },
            "target": "https://example.com",
        },
    ])
    rendered = output.getvalue()
    assert "8.8.8.8" in rendered
    assert "EXAMPLE.COM" in rendered
    assert "Example Registrar" in rendered
    assert "8.8.8.0/24" in rendered
    assert "PUBLIC-DNS" in rendered
    assert "origin" in rendered.lower()


def test_rendering_displays_admin_email_ports_and_cms_details(monkeypatch):
    from io import StringIO
    from rich.console import Console
    import stari.ui as ui

    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, force_terminal=False, color_system=None))
    rows = [
        {
            "check_id": "ADMIN_PANEL_DISCOVERY", "target": "https://example.com",
            "evidence": {"candidates": [{"path": "/admin/", "http_status": 200,
                                        "classification": "VERIFIED_ADMIN_LOGIN",
                                        "final_url": "https://example.com/admin/"}],
                         "baseline_available": True},
        },
        {
            "check_id": "PUBLIC_EMAIL_DISCOVERY", "target": "https://example.com",
            "evidence": {"emails": ["security@example.com"]},
        },
        {
            "check_id": "WEB_TCP_PORTS", "target": "https://example.com",
            "evidence": {"ports": [{"port": 443, "state": "OPEN", "service_hint": "HTTPS"}]},
        },
        {
            "check_id": "CMS_FINGERPRINT", "target": "https://example.com",
            "evidence": {"detected": [{"name": "WordPress", "signals": ["/wp-content/"]}]},
        },
    ]
    for mode in ("admin", "emails", "ports", "cms"):
        ui.render_scan_details(mode, [row for row in rows if row["check_id"].startswith({
            "admin": "ADMIN_", "emails": "PUBLIC_", "ports": "WEB_", "cms": "CMS_"
        }[mode])])
    printed = output.getvalue()
    assert "/admin/" in printed
    assert "security@example.com" in printed
    assert "443" in printed
    assert "WordPress" in printed
