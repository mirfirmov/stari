import asyncio
from urllib.parse import parse_qs, urlsplit

from stari.core.config import make_config
from stari.core.models import HTTPResult
from stari.engines.parameter_audit import check_sqli_boolean_and_error, check_xss_reflection


class FakeClient:
    def __init__(self, mode):
        self.config = make_config("https://example.com")
        self.mode = mode
        self.calls = []

    async def get(self, url):
        self.calls.append(url)
        parsed = urlsplit(url)
        if parsed.path == "/":
            body = b'<html><a href="/search?q=hello">search</a><a href="https://outside.test/?q=no">external</a></html>'
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)
        if parsed.path == "/sitemap.xml":
            return HTTPResult(url, 404, {"content-type": "text/plain"}, b"not found")

        value = parse_qs(parsed.query).get("q", [""])[0]
        if self.mode == "xss":
            if "<stari-probe" in value:
                body = f"<html><body>Search result: {value}</body></html>".encode()
            else:
                body = b"<html><body>Search result: hello</body></html>"
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

        if value.endswith("'") and self.mode != "boolean":
            body = b"SQLite error: near quote: syntax error"
        elif "AND '1'='1" in value or "AND 1=1" in value:
            body = b"<html><body>Product found: 1</body></html>"
        elif "AND '1'='2" in value or "AND 1=2" in value:
            body = b"<html><body>EMPTY_RESULT_SENTINEL: no matching records; pagination unavailable; please refine your search and try again.</body></html>"
        else:
            body = b"<html><body>Product found: 1</body></html>"
        return HTTPResult(url, 200, {"content-type": "text/html"}, body)


def test_xss_reflection_uses_non_executable_html_canary_and_stays_in_scope():
    client = FakeClient("xss")
    rows = asyncio.run(check_xss_reflection(client, "https://example.com"))
    evidence = rows[0].evidence
    assert rows[0].status == "NEEDS_REVIEW"
    assert evidence["javascript_execution"] is False
    assert evidence["results"][0]["classification"] == "UNESCAPED_HTML_REFLECTION"
    assert all(urlsplit(url).hostname == "example.com" for url in client.calls)


def test_sqli_detects_error_signature_and_boolean_difference_without_time_probes():
    client = FakeClient("sqli")
    rows = asyncio.run(check_sqli_boolean_and_error(client, "https://example.com"))
    evidence = rows[0].evidence
    assert rows[0].status == "NEEDS_REVIEW"
    assert evidence["findings"]
    assert "DATABASE_ERROR_SIGNATURE" in evidence["findings"][0]["signals"]
    assert evidence["time_based_probes"] is False
    assert evidence["stacked_queries"] is False
    assert evidence["state_changing_methods"] is False


def test_xss_reports_no_candidate_when_query_urls_are_missing():
    class EmptyClient(FakeClient):
        async def get(self, url):
            if urlsplit(url).path == "/":
                return HTTPResult(url, 200, {"content-type": "text/html"}, b"<html>no query links</html>")
            return HTTPResult(url, 404, {"content-type": "text/plain"}, b"not found")

    rows = asyncio.run(check_xss_reflection(EmptyClient("xss"), "https://example.com"))
    assert rows[0].status == "NO_CANDIDATE_URLS"
    assert rows[0].evidence["probes_sent"] == 0


def test_xss_html_escaped_canary_is_not_reported_as_potential():
    class EscapedClient(FakeClient):
        async def get(self, url):
            self.calls.append(url)
            parsed = urlsplit(url)
            if parsed.path == "/":
                return HTTPResult(url, 200, {"content-type": "text/html"}, b'<a href="/search?q=hello">search</a>')
            if parsed.path == "/sitemap.xml":
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            value = parse_qs(parsed.query).get("q", [""])[0]
            if "stari-probe" in value:
                value = value.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><body>{value}</body></html>".encode()
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    rows = asyncio.run(check_xss_reflection(EscapedClient("xss"), "https://example.com"))
    assert rows[0].status == "REFLECTION_ESCAPED"
    assert not rows[0].evidence["results"] or all(
        item["classification"] != "UNESCAPED_HTML_REFLECTION"
        for item in rows[0].evidence["results"]
    )
    endpoint_query = parse_qs(urlsplit(rows[0].evidence["results"][0]["endpoint"]).query)
    assert endpoint_query["q"] == ["[redacted]"]


def test_sqli_boolean_pair_is_recorded_when_true_and_false_responses_differ():
    client = FakeClient("boolean")
    rows = asyncio.run(check_sqli_boolean_and_error(client, "https://example.com"))
    findings = rows[0].evidence["findings"]
    assert findings
    assert "BOOLEAN_RESPONSE_DIFFERENTIAL" in findings[0]["signals"]
    assert "DATABASE_ERROR_SIGNATURE" not in findings[0]["signals"]


def test_parameter_candidate_filter_skips_state_changing_query_actions():
    from stari.engines.parameter_audit import _valid_candidate
    from stari.engines.http_client import SafeHTTPClient
    from stari.core.config import make_config

    class ClientScope:
        config = make_config("https://example.com")

    client = ClientScope()
    assert not _valid_candidate("https://example.com/?action=delete&id=3", client)
    assert not _valid_candidate("https://example.com/?do=logout&next=%2F", client)
    assert _valid_candidate("https://example.com/search?q=flowers", client)
