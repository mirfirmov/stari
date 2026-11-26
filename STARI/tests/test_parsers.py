from stari.core.config import make_config
from stari.engines.robots import parse_robots
from stari.engines.sitemap import parse_sitemap


def test_robots_extracts_common_directives():
    result = parse_robots("""User-agent: *
Disallow: /admin
Allow: /public
Sitemap: https://example.com/sitemap.xml
""")
    assert result["disallow"] == ["/admin"]
    assert result["allow"] == ["/public"]
    assert result["sitemap"] == ["https://example.com/sitemap.xml"]


def test_sitemap_ignores_out_of_scope_urls():
    config = make_config("https://example.com")
    xml = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/</loc></url>
      <url><loc>https://other.example.net/private</loc></url>
    </urlset>"""
    locations, ignored = parse_sitemap(xml, config.base_url, config)
    assert locations == ["https://example.com/"]
    assert ignored == 1


def test_robots_observation_keeps_raw_content_and_directives():
    import asyncio

    from stari.core.config import make_config
    from stari.core.models import HTTPResult
    from stari.engines.robots import check_robots

    class FakeClient:
        config = make_config("https://example.com")

        async def get(self, url):
            body = b"User-agent: *\nDisallow: /private\nAllow: /public\n"
            return HTTPResult(
                url=url,
                status_code=200,
                headers={"content-type": "text/plain; charset=utf-8"},
                body=body,
            )

    observation = asyncio.run(check_robots(FakeClient(), "https://example.com"))[0]
    assert observation.evidence["content"].startswith("User-agent: *")
    assert observation.evidence["disallow"] == ["/private"]
    assert "/private" in observation.evidence["content"]
    assert observation.evidence["http_status"] == 200


def test_robots_reports_out_of_scope_redirect_without_following():
    import asyncio

    from stari.core.config import make_config
    from stari.core.models import HTTPResult
    from stari.engines.robots import check_robots

    class FakeClient:
        config = make_config("https://example.com")

        async def get(self, url):
            return HTTPResult(
                url=url,
                status_code=301,
                headers={"location": "https://www.example.com/robots.txt"},
                body=b"",
            )

    observation = asyncio.run(check_robots(FakeClient(), "https://example.com"))[0]
    assert observation.evidence["http_status"] == 301
    assert "outside the configured scope" in observation.details
    assert observation.evidence["location"] == "https://www.example.com/robots.txt"
