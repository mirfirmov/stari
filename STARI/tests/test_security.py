import asyncio

from stari.core.config import make_config
from stari.core.models import HTTPResult
from stari.engines.security import TEST_ORIGIN, check_cors


class FakeHTTPClient:
    def __init__(self, headers):
        self.config = make_config("https://example.com")
        self.headers = headers
        self.calls = []

    async def get(self, url, *, extra_headers=None):
        self.calls.append((url, extra_headers or {}))
        return HTTPResult(url, 200, self.headers, b"ok")


def test_cors_detects_reflected_origin_with_credentials():
    client = FakeHTTPClient({
        "access-control-allow-origin": TEST_ORIGIN,
        "access-control-allow-credentials": "true",
        "vary": "Origin",
    })
    rows = asyncio.run(check_cors(client, "https://example.com"))
    assert rows[0].status == "REFLECTED_ORIGIN_WITH_CREDENTIALS"
    assert rows[0].severity == "MEDIUM"
    assert client.calls[0][1] == {"Origin": TEST_ORIGIN}
    assert rows[0].evidence["credentials_sent"] is False


def test_cors_wildcard_without_credentials_is_observation():
    client = FakeHTTPClient({"access-control-allow-origin": "*"})
    rows = asyncio.run(check_cors(client, "https://example.com"))
    assert rows[0].status == "WILDCARD_PUBLIC_RESOURCE"
    assert rows[0].severity == "INFO"


def test_cors_no_header_is_not_a_finding():
    client = FakeHTTPClient({})
    rows = asyncio.run(check_cors(client, "https://example.com"))
    assert rows[0].status == "NO_CORS_ALLOW_ORIGIN"
    assert rows[0].severity == "INFO"


def test_cors_wildcard_with_credentials_is_not_misreported_as_exploitable():
    client = FakeHTTPClient({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    rows = asyncio.run(check_cors(client, "https://example.com"))
    assert rows[0].status == "WILDCARD_WITH_CREDENTIALS_REJECTED_BY_BROWSERS"
    assert rows[0].severity == "INFO"
