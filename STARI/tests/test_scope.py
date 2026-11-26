from pathlib import Path

import pytest

from stari.core.config import make_config, normalize_target
from stari.core.scope import is_in_scope


def test_normalize_host_adds_https():
    origin, host = normalize_target("Example.COM")
    assert origin == "https://example.com"
    assert host == "example.com"


def test_normalize_target_rejects_path():
    with pytest.raises(ValueError):
        normalize_target("https://example.com/admin")


def test_scope_is_exact_host_not_wildcard():
    config = make_config("example.com")
    assert is_in_scope("https://example.com/robots.txt", config)
    assert not is_in_scope("https://admin.example.com/", config)
    assert not is_in_scope("https://example.net/", config)
    assert not is_in_scope("http://example.com/", config)
    assert not is_in_scope("https://example.com:8443/", config)


def test_scope_rejects_non_http_scheme():
    config = make_config("example.com")
    assert not is_in_scope("ftp://example.com/file", config)


def test_stari_project_defaults():
    config = make_config("https://parovoz.tv", "parovoz.tv")
    assert config.project_name == "parovoz.tv"
    assert config.base_url == "https://parovoz.tv"
    assert config.allowed_hosts == ["parovoz.tv"]
    assert config.user_agent.startswith("STARI-CLI/")


def test_config_round_trip_uses_stari_directory(tmp_path):
    from stari.core.config import load_config, save_config

    config = make_config("https://parovoz.tv", "parovoz.tv")
    saved_path = save_config(config, tmp_path)
    assert saved_path == tmp_path / ".stari" / "config.json"
    loaded = load_config(tmp_path)
    assert loaded.to_dict() == config.to_dict()


def test_scope_supports_explicitly_added_hosts():
    config = make_config("https://example.com")
    config.allowed_hosts.append("www.example.com")
    assert is_in_scope("https://www.example.com/robots.txt", config)
    assert not is_in_scope("https://sub.example.com/robots.txt", config)


def test_http_client_follows_only_in_scope_redirects(monkeypatch):
    import asyncio

    from stari.core.config import make_config
    from stari.engines.http_client import SafeHTTPClient

    class FakeResponse:
        def __init__(self, url, status_code, headers=None, body=b""):
            self.url = url
            self.status_code = status_code
            self.headers = headers or {}
            self.body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def aiter_bytes(self):
            yield self.body

    class FakeTransport:
        def __init__(self):
            self.calls = []

        def stream(self, method, url):
            self.calls.append(url)
            if url == "https://example.com/robots.txt":
                return FakeResponse(
                    url, 302, {"location": "/security/robots.txt"}, b""
                )
            return FakeResponse(url, 200, {"content-type": "text/plain"}, b"User-agent: *")

    async def run():
        config = make_config("https://example.com")
        client = SafeHTTPClient(config)
        transport = FakeTransport()
        client._client = transport

        async def no_pace():
            return None

        monkeypatch.setattr(client, "_pace", no_pace)
        result = await client.get("https://example.com/robots.txt")
        return result, transport.calls

    result, calls = asyncio.run(run())
    assert result.status_code == 200
    assert result.text == "User-agent: *"
    assert len(result.redirect_history) == 1
    assert calls == [
        "https://example.com/robots.txt",
        "https://example.com/security/robots.txt",
    ]


def test_http_client_does_not_follow_redirect_to_unlisted_host(monkeypatch):
    import asyncio

    from stari.core.config import make_config
    from stari.engines.http_client import SafeHTTPClient

    class FakeResponse:
        def __init__(self, url, status_code, headers=None, body=b""):
            self.url = url
            self.status_code = status_code
            self.headers = headers or {}
            self.body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def aiter_bytes(self):
            yield self.body

    class FakeTransport:
        def __init__(self):
            self.calls = []

        def stream(self, method, url):
            self.calls.append(url)
            return FakeResponse(
                url, 301, {"location": "https://www.example.com/robots.txt"}, b""
            )

    async def run():
        client = SafeHTTPClient(make_config("https://example.com"))
        transport = FakeTransport()
        client._client = transport

        async def no_pace():
            return None

        monkeypatch.setattr(client, "_pace", no_pace)
        result = await client.get("https://example.com/robots.txt")
        return result, transport.calls

    result, calls = asyncio.run(run())
    assert result.status_code == 301
    assert result.headers["location"] == "https://www.example.com/robots.txt"
    assert calls == ["https://example.com/robots.txt"]


def test_http_client_allows_only_synthetic_origin_override(monkeypatch):
    import asyncio
    import pytest

    from stari.core.config import make_config
    from stari.engines.http_client import SafeHTTPClient

    class FakeResponse:
        url = "https://example.com/"
        status_code = 200
        headers = {"content-type": "text/plain"}
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def aiter_bytes(self): yield b"ok"

    class FakeTransport:
        def __init__(self): self.calls = []
        def stream(self, method, url, headers=None):
            self.calls.append((method, url, headers))
            return FakeResponse()

    async def run():
        client = SafeHTTPClient(make_config("https://example.com"))
        transport = FakeTransport()
        client._client = transport
        async def no_pace(): return None
        monkeypatch.setattr(client, "_pace", no_pace)
        await client.get("https://example.com/", extra_headers={"Origin": "https://stari.invalid"})
        return transport.calls

    calls = asyncio.run(run())
    assert calls[0][2] == {"Origin": "https://stari.invalid"}

    async def invalid():
        client = SafeHTTPClient(make_config("https://example.com"))
        client._client = FakeTransport()
        await client.get("https://example.com/", extra_headers={"Cookie": "secret=value"})

    with pytest.raises(ValueError):
        asyncio.run(invalid())
