import asyncio
from urllib.parse import urlsplit

from stari.core.config import make_config
from stari.core.models import HTTPResult
from stari.engines.admin_finder import check_admin_panels


NOT_FOUND = b"<html><title>Not found</title><h1>Page not found</h1><p>The requested resource does not exist.</p></html>"
ADMIN_LOGIN = (
    b'<html><title>Admin Login</title><h1>Administration</h1>'
    b'<form action="/admin/login"><input name="username">'
    b'<input type="password" name="password"><button>Sign in</button></form></html>'
)


class FakeClient:
    def __init__(self):
        self.config = make_config("https://example.com")

    async def get(self, url):
        if "__stari_missing_" in url:
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
        if url.endswith("/admin/"):
            return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)
        return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)


def test_admin_finder_detects_admin_login_form_and_filters_404():
    rows = asyncio.run(check_admin_panels(FakeClient(), "https://example.com", paths=("admin/", "administrator/")))
    evidence = rows[0].evidence
    assert evidence["checked_paths"] == 2
    assert evidence["candidate_count"] == 1
    assert evidence["candidates"][0]["path"] == "/admin/"
    assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"
    assert evidence["candidates"][0]["confidence"] == "HIGH"
    assert evidence["baseline_samples"] == 3


def test_admin_finder_rejects_path_traversal_candidates():
    rows = asyncio.run(check_admin_panels(FakeClient(), "https://example.com", paths=("../outside", "admin/")))
    assert rows[0].evidence["checked_paths"] == 1


def test_admin_finder_does_not_treat_generic_200_as_admin_panel():
    class Generic200Client:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, b"<html><title>Welcome</title><h1>News</h1><p>Public website content</p></html>")

    evidence = asyncio.run(check_admin_panels(Generic200Client(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["unclassified_route_count"] == 1


def test_admin_finder_does_not_match_login_word_in_footer_only():
    class FooterLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = b"<html><title>News</title><h1>Latest news</h1><footer>Login to your account</footer></html>"
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(FooterLoginClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0


def test_admin_finder_separates_regular_login_from_admin_panel():
    class RegularLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, (
                b'<html><title>Sign in</title><form><input name="email" type="email">'
                b'<input name="password" type="password"><button>Sign in</button></form></html>'
            ))

    evidence = asyncio.run(check_admin_panels(RegularLoginClient(), "https://example.com", paths=("login/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["related_login_page_count"] == 1
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["path"] == "/login/"


def test_admin_finder_never_reports_403_as_an_existing_admin_panel():
    class RestrictedClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 403, {"content-type": "text/html"}, b"<title>Forbidden</title><h1>Access denied to administration</h1>")

    evidence = asyncio.run(check_admin_panels(RestrictedClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert evidence["restricted_unverified_count"] == 1


def test_admin_finder_filters_global_403_waf_template():
    class WAFClient:
        config = make_config("https://example.com")

        async def get(self, url):
            body = b"<html><title>Request blocked</title><h1>Access denied</h1><p>Reference: 123456789012</p></html>"
            return HTTPResult(url, 403, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(WAFClient(), "https://example.com", paths=("admin/", "login/")))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["restricted_unverified_count"] == 2


def test_admin_finder_excludes_out_of_scope_redirects():
    class RedirectClient:
        config = make_config("https://example.com")

        async def get(self, url):
            return HTTPResult(url, 302, {"location": "https://outside.example.net/"}, b"")

    evidence = asyncio.run(check_admin_panels(RedirectClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["out_of_scope_redirects_excluded"] == 1


def test_admin_finder_detects_login_form_after_internal_redirect():
    class InternalRedirectClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(
                "https://example.com/login?next=%2Fadmin%2F", 200,
                {"content-type": "text/html"}, ADMIN_LOGIN,
                redirect_history=[{"status_code": 302, "from": url, "to": "https://example.com/login"}],
            )

    evidence = asyncio.run(check_admin_panels(InternalRedirectClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 1
    assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"


def test_admin_finder_fails_closed_when_control_baseline_is_unavailable():
    class NoBaselineClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                raise TimeoutError("control path timed out")
            return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)

    evidence = asyncio.run(check_admin_panels(NoBaselineClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert evidence["baseline_available"] is False
    assert evidence["baseline_stable"] is False
    assert len(evidence["baseline_errors"]) == 3


def test_admin_finder_ignores_soft_404_with_dynamic_request_ids():
    class Dynamic404Client:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                token = url.split("__stari_missing_", 1)[1]
            else:
                token = "f" * 32
            body = f"<html><title>Not found</title><h1>Missing page</h1><p>Reference: {token}</p></html>".encode()
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(Dynamic404Client(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["soft_404_filtered"] == 1


def test_admin_php_login_form_is_recognized_as_admin_route():
    class AdminPhpClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)

    evidence = asyncio.run(check_admin_panels(AdminPhpClient(), "https://example.com", paths=("admin.php",)))[0].evidence
    assert evidence["candidate_count"] == 1
    assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"


def test_admin_finder_filters_waf_page_that_reflects_requested_path():
    class ReflectedWAFClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            body = f"<html><title>Request blocked</title><h1>Access denied</h1><p>Blocked URI: {path}</p></html>".encode()
            return HTTPResult(url, 403, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(ReflectedWAFClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["soft_404_filtered"] == 0
    assert evidence["restricted_unverified_count"] == 1


def test_admin_finder_never_reports_401_as_an_existing_admin_panel():
    class AuthRequiredClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 401, {"www-authenticate": 'Basic realm="admin"'}, b"Authentication required")

    evidence = asyncio.run(check_admin_panels(AuthRequiredClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert evidence["restricted_unverified_count"] == 1


def test_admin_route_with_password_and_identity_fields_is_detected_without_admin_copy():
    class FormOnlyAdminClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = b'<html><title>Secure Access</title><form><input name="username"><input type="password" name="password"></form></html>'
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(FormOnlyAdminClient(), "https://example.com", paths=("admin.php",)))[0].evidence
    assert evidence["candidate_count"] == 1
    assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"
    assert evidence["candidates"][0]["admin_like_path"] is True


def test_admin_finder_filters_same_soft404_body_even_if_status_changes():
    class StatusChanging404Client:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(check_admin_panels(StatusChanging404Client(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["soft_404_filtered"] == 1


def test_admin_finder_end_to_end_against_local_http_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from stari.engines.http_client import SafeHTTPClient

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/__stari_missing_"):
                status, body = 404, NOT_FOUND
            elif self.path == "/admin/":
                status, body = 200, ADMIN_LOGIN
            else:
                status, body = 404, NOT_FOUND
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = make_config(f"http://127.0.0.1:{server.server_port}")
        config.requests_per_second = 100.0

        async def run():
            async with SafeHTTPClient(config) as client:
                return await check_admin_panels(client, config.base_url, paths=("admin/",))

        evidence = asyncio.run(run())[0].evidence
        assert evidence["candidate_count"] == 1
        assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)



def test_admin_finder_discovers_admin_paths_from_robots_txt_and_checks_them():
    class RobotsAdvertisedAdminClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if url.endswith("/robots.txt"):
                body = b"User-agent: *\\nDisallow: /admin-console/\\nDisallow: /console\\nDisallow: /private/\\nAllow: /admin/login\\n" \
                    .replace(b"\\n", b"\n")
                return HTTPResult(url, 200, {"content-type": "text/plain"}, body)
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if url.endswith("/admin-console/") or url.endswith("/console") or url.endswith("/admin/login"):
                return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(RobotsAdvertisedAdminClient(), "https://example.com", paths=())
    )[0].evidence
    assert evidence["robots_http_status"] == 200
    assert evidence["robots_admin_path_hint_count"] == 3
    assert evidence["candidate_count"] == 3
    assert all(item["source"].startswith("robots.txt:") for item in evidence["candidates"])


def test_admin_finder_includes_exact_console_path_in_builtin_candidates():
    class ConsoleAdminClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if url.endswith("/robots.txt"):
                return HTTPResult(url, 404, {}, b"")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if url.rstrip("/").endswith("/console"):
                return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(ConsoleAdminClient(), "https://example.com")
    )[0].evidence
    console_hits = [item for item in evidence["candidates"] if item["path"].rstrip("/") == "/console"]
    assert console_hits
    assert console_hits[0]["source"] == "built-in"
    assert console_hits[0]["classification"] == "VERIFIED_ADMIN_LOGIN"


def test_admin_finder_ignores_non_admin_robots_disallow_paths():
    class RobotsNoiseClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if url.endswith("/robots.txt"):
                return HTTPResult(
                    url, 200, {"content-type": "text/plain"},
                    b"User-agent: *\nDisallow: /private/\nDisallow: /images/\nDisallow: /tmp/\nDisallow: /\n",
                )
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(RobotsNoiseClient(), "https://example.com", paths=())
    )[0].evidence
    assert evidence["robots_admin_path_hint_count"] == 0
    assert evidence["checked_paths"] == 0
    assert evidence["candidate_count"] == 0


def test_admin_finder_deduplicates_robots_and_builtin_console():
    class DuplicateConsoleClient:
        config = make_config("https://example.com")
        requested: list[str] = []

        async def get(self, url):
            self.requested.append(url)
            if url.endswith("/robots.txt"):
                return HTTPResult(url, 200, {"content-type": "text/plain"}, b"User-agent: *\nDisallow: /console\n")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    client = DuplicateConsoleClient()
    asyncio.run(check_admin_panels(client, "https://example.com", paths=("console", "console/")))
    console_requests = [url for url in client.requested if url.rstrip("/").endswith("/console")]
    assert len(console_requests) == 1



def test_admin_finder_end_to_end_robots_txt_discovers_console_route():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from stari.engines.http_client import SafeHTTPClient

    robots_body = b"User-agent: *\nDisallow: /console\nDisallow: /admin-area/\nDisallow: /private/\n"
    console_body = (
        b'<html><title>Console Login</title><h1>Administration Console</h1>'
        b'<form action="/console/session"><input name="username">'
        b'<input type="password" name="password"><button>Sign in</button></form></html>'
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                status, body, content_type = 200, robots_body, "text/plain"
            elif self.path.startswith("/__stari_missing_"):
                status, body, content_type = 404, NOT_FOUND, "text/html"
            elif self.path == "/console":
                status, body, content_type = 200, console_body, "text/html"
            else:
                status, body, content_type = 404, NOT_FOUND, "text/html"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = make_config(f"http://127.0.0.1:{server.server_port}")
        config.requests_per_second = 100.0

        async def run():
            async with SafeHTTPClient(config) as client:
                return await check_admin_panels(client, config.base_url, paths=())

        evidence = asyncio.run(run())[0].evidence
        assert evidence["robots_http_status"] == 200
        assert evidence["robots_admin_path_hint_count"] == 2
        assert evidence["candidate_count"] == 1
        candidate = evidence["candidates"][0]
        assert candidate["path"] == "/console"
        assert candidate["source"] == "robots.txt: Disallow"
        assert candidate["classification"] == "VERIFIED_ADMIN_LOGIN"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)



def test_admin_finder_rejects_admin_wording_without_functional_controls():
    class StaticAdminTextClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"},
                              b"<html><title>Admin Dashboard</title><h1>Admin Dashboard</h1><p>Documentation page</p></html>")

    evidence = asyncio.run(check_admin_panels(StaticAdminTextClient(), "https://example.com", paths=("console",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert evidence["weak_signal_ignored_count"] == 1


def test_admin_finder_detects_client_rendered_login_controls_outside_a_form_element():
    class LooseFieldsClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = b"<html><title>Secure Access</title><input name='username'><input type='password' name='password'></html>"
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    evidence = asyncio.run(check_admin_panels(LooseFieldsClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 1
    assert evidence["candidates"][0]["classification"] == "VERIFIED_ADMIN_LOGIN"


def test_admin_finder_rejects_inconsistent_random_control_responses():
    class UnstableControlsClient:
        config = make_config("https://example.com")
        control_index = 0

        async def get(self, url):
            if "__stari_missing_" in url:
                self.control_index += 1
                status = 404 if self.control_index < 3 else 503
                return HTTPResult(url, status, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)

    evidence = asyncio.run(check_admin_panels(UnstableControlsClient(), "https://example.com", paths=("admin/",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert evidence["baseline_stable"] is False


def test_admin_finder_does_not_serialize_unverified_robots_hints_as_findings():
    class RobotsHintOnlyClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if url.endswith("/robots.txt"):
                return HTTPResult(url, 200, {"content-type": "text/plain"}, b"User-agent: *\nDisallow: /console\n")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, b"<html><title>Welcome</title><h1>Public page</h1></html>")

    evidence = asyncio.run(check_admin_panels(RobotsHintOnlyClient(), "https://example.com", paths=()))[0].evidence
    assert evidence["robots_admin_path_hint_count"] == 1
    assert evidence["candidate_count"] == 0
    assert evidence["candidates"] == []
    assert "robots_admin_paths" not in evidence


def test_admin_finder_discovers_russian_login_form_from_homepage_link():
    class RussianLinkedLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path == "/robots.txt" or path == "/sitemap.xml":
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"", "/"}:
                body = b'<html><body><a href="/private-area">\xd0\x92\xd0\xbe\xd0\xb9\xd1\x82\xd0\xb8</a></body></html>'
                return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)
            if path == "/private-area":
                body = (
                    '<html><head><title>Вход</title></head><body><div class="auth">'
                    '<h1>Вход в личный кабинет</h1>'
                    '<input name="username" placeholder="Логин">'
                    '<input type="password" name="password" placeholder="Пароль">'
                    '<button>Войти</button></div></body></html>'
                ).encode("utf-8")
                return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(RussianLinkedLoginClient(), "https://example.com", paths=())
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 1
    login = evidence["login_pages"][0]
    assert login["path"] == "/private-area"
    assert login["source"].startswith("homepage-link: Войти")
    assert login["classification"] == "LOGIN_PAGE"
    assert login["confidence"] == "MEDIUM"


def test_admin_finder_detects_login_form_rendered_on_homepage():
    class HomepageLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"/robots.txt", "/sitemap.xml"}:
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"", "/"}:
                return HTTPResult(url, 200, {"content-type": "text/html"}, (
                    b'<html><h1>Sign in</h1><form><input type="email" name="email">'
                    b'<input type="password" name="password"><button>Continue</button></form></html>'
                ))
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(HomepageLoginClient(), "https://example.com", paths=())
    )[0].evidence
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["path"] == "/"
    assert evidence["login_pages"][0]["source"] == "homepage"


def test_admin_finder_discovers_login_route_from_sitemap():
    class SitemapLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path == "/robots.txt":
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            if path == "/sitemap.xml":
                xml = b'<?xml version="1.0"?><urlset><url><loc>https://example.com/account/sign-in</loc></url></urlset>'
                return HTTPResult(url, 200, {"content-type": "application/xml"}, xml)
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path == "/account/sign-in":
                return HTTPResult(url, 200, {"content-type": "text/html"}, (
                    b'<html><form><input name="email" type="email">'
                    b'<input name="password" type="password"><button>Sign in</button></form></html>'
                ))
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(SitemapLoginClient(), "https://example.com", paths=())
    )[0].evidence
    assert evidence["sitemap_candidate_count"] == 1
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["path"] == "/account/sign-in"
    assert evidence["login_pages"][0]["source"] == "sitemap.xml"


def test_admin_finder_reports_russian_login_when_inputs_are_outside_form():
    class RussianFieldsClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                '<html><title>Авторизация</title><div>'
                '<input placeholder="Введите логин">'
                '<input type="password" placeholder="Пароль">'
                '<button>Войти</button></div></html>'
            ).encode("utf-8")
            return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)

    evidence = asyncio.run(
        check_admin_panels(RussianFieldsClient(), "https://example.com", paths=("login/",))
    )[0].evidence
    assert evidence["login_page_count"] == 1
    assert evidence["candidate_count"] == 0
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["password_field_count"] == 1
    assert evidence["login_pages"][0]["identity_field_count"] == 1


def test_admin_finder_shows_external_auth_redirect_without_requesting_it_or_saving_query():
    class ExternalLoginRedirectClient:
        config = make_config("https://example.com")
        requested: list[str] = []

        async def get(self, url):
            self.requested.append(url)
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path == "/console":
                return HTTPResult(url, 302, {"location": "https://identity.example.net/sign-in?code=secret-token"}, b"")
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    client = ExternalLoginRedirectClient()
    evidence = asyncio.run(
        check_admin_panels(client, "https://example.com", paths=("console",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["out_of_scope_redirects_excluded"] == 1
    assert len(evidence["external_redirects"]) == 1
    item = evidence["external_redirects"][0]
    assert item["path"] == "/console"
    assert item["destination"] == "https://identity.example.net/sign-in"
    assert "secret-token" not in repr(item)
    assert not any("identity.example.net" in url for url in client.requested)


def test_admin_finder_recognizes_passwordless_email_login_with_visible_login_cue():
    class PasswordlessEmailLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                '<html><head><title>Вход</title></head><body><h1>Войти в аккаунт</h1>'
                '<form action="/auth/send-code"><input type="email" name="email">'
                '<button type="submit">Получить код</button></form></body></html>'
            ).encode("utf-8")
            return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)

    evidence = asyncio.run(
        check_admin_panels(PasswordlessEmailLoginClient(), "https://example.com", paths=("account/access",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["password_field_count"] == 0
    assert evidence["login_pages"][0]["identity_field_count"] == 1


def test_admin_finder_recognizes_passwordless_phone_login_with_visible_login_cue():
    class PasswordlessPhoneLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                '<html><h1>Вход по номеру телефона</h1><div class="auth">'
                '<input type="tel" name="phone" autocomplete="tel">'
                '<button>Получить код</button></div></html>'
            ).encode("utf-8")
            return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)

    evidence = asyncio.run(
        check_admin_panels(PasswordlessPhoneLoginClient(), "https://example.com", paths=("personal-area",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["password_field_count"] == 0
    assert evidence["login_pages"][0]["identity_field_count"] == 1


def test_admin_finder_recognizes_passwordless_email_login_with_visible_login_cue():
    class PasswordlessEmailLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                '<html><head><title>Вход</title></head><body><h1>Войти в аккаунт</h1>'
                '<form action="/auth/send-code"><input type="email" name="email">'
                '<button type="submit">Получить код</button></form></body></html>'
            ).encode("utf-8")
            return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)

    evidence = asyncio.run(
        check_admin_panels(PasswordlessEmailLoginClient(), "https://example.com", paths=("account/access",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["password_field_count"] == 0
    assert evidence["login_pages"][0]["identity_field_count"] == 1


def test_admin_finder_recognizes_passwordless_phone_login_with_visible_login_cue():
    class PasswordlessPhoneLoginClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"", "/", "/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                '<html><h1>Вход по номеру телефона</h1><div class="auth">'
                '<input type="tel" name="phone" autocomplete="tel">'
                '<button>Получить код</button></div></html>'
            ).encode("utf-8")
            return HTTPResult(url, 200, {"content-type": "text/html; charset=utf-8"}, body)

    evidence = asyncio.run(
        check_admin_panels(PasswordlessPhoneLoginClient(), "https://example.com", paths=("personal-area",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"
    assert evidence["login_pages"][0]["password_field_count"] == 0
    assert evidence["login_pages"][0]["identity_field_count"] == 1


def test_admin_finder_reports_out_of_scope_login_link_and_related_subdomain_without_requesting():
    class LinkedSubdomainsClient:
        config = make_config("https://example.com")
        requested: list[str] = []

        async def get(self, url):
            self.requested.append(url)
            path = urlsplit(url).path
            if path in {"/robots.txt", "/sitemap.xml"} or "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"", "/"}:
                body = (
                    '<html><a href="https://auth.example.net/sign-in">Войти</a>'
                    '<a href="https://blog.example.com/">Блог</a></html>'
                ).encode("utf-8")
                return HTTPResult(url, 200, {"content-type": "text/html"}, body)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    client = LinkedSubdomainsClient()
    evidence = asyncio.run(
        check_admin_panels(client, "https://example.com", paths=())
    )[0].evidence
    assert evidence["external_login_links"][0]["destination"] == "https://auth.example.net/sign-in"
    assert evidence["external_login_links"][0]["status"] == "OUT_OF_SCOPE_NOT_REQUESTED"
    assert evidence["related_subdomain_links"][0]["host"] == "blog.example.com"
    assert evidence["related_subdomain_links"][0]["status"] == "OUT_OF_SCOPE_NOT_REQUESTED"
    assert not any("auth.example.net" in url or "blog.example.com" in url for url in client.requested)


def test_admin_finder_recognizes_custom_field_classes_and_data_testids():
    class CustomFieldClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if "__stari_missing_" in url or path in {"", "/robots.txt", "/sitemap.xml"}:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            body = (
                b'<html><head><title>Control Center</title></head><body>'
                b'<main><div class="control-center-login"><input class="account-field" '
                b'data-testid="username-input" type="text">'
                b'<input class="secret-field" data-testid="password-input" type="password">'
                b'<button role="button">Continue</button></div></main></body></html>'
            )
            return HTTPResult(url, 200, {"content-type": "text/html"}, body)

    evidence = asyncio.run(
        check_admin_panels(CustomFieldClient(), "https://example.com", paths=("/control-center/login",))
    )[0].evidence
    assert evidence["candidate_count"] == 1
    item = evidence["candidates"][0]
    assert item["classification"] == "VERIFIED_ADMIN_LOGIN"
    assert item["password_field_count"] == 1
    assert item["identity_field_count"] == 1


def test_admin_finder_finds_custom_login_path_from_nonstandard_account_link():
    class CustomPathClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path == "/robots.txt" or path == "/sitemap.xml":
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"", "/"}:
                return HTTPResult(url, 200, {"content-type": "text/html"},
                    '<html><header><a href="/my-workspace">Мой кабинет</a></header></html>'.encode())
            if path == "/my-workspace":
                return HTTPResult(url, 200, {"content-type": "text/html"}, (
                    '<html><head><title>Welcome back</title></head><body>'
                    '<div class="auth-panel"><input class="identity" type="email" autocomplete="username">'
                    '<input class="secret" type="password"><button>Continue</button></div>'
                    '</body></html>'
                ).encode())
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(check_admin_panels(CustomPathClient(), "https://example.com", paths=()))[0].evidence
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["path"] == "/my-workspace"
    assert evidence["login_pages"][0]["classification"] == "LOGIN_PAGE"


def test_admin_finder_keeps_sso_login_entry_separate_from_homepage_link():
    class SSOClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if path in {"/robots.txt", "/sitemap.xml"}:
                return HTTPResult(url, 404, {"content-type": "text/plain"}, b"")
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"", "/"}:
                return HTTPResult(url, 200, {"content-type": "text/html"},
                    b'<html><a href="/access">Sign in</a></html>')
            if path == "/access":
                return HTTPResult(url, 200, {"content-type": "text/html"},
                    b'<html><title>Continue with company SSO</title>'
                    b'<a href="/oauth/authorize">Continue with company SSO</a></html>')
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(check_admin_panels(SSOClient(), "https://example.com", paths=()))[0].evidence
    assert evidence["login_page_count"] == 1
    assert evidence["login_pages"][0]["path"] == "/access"


def test_admin_finder_reports_strong_login_as_observed_when_controls_are_unavailable():
    class BrokenControlsClient:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                raise TimeoutError("random route timed out")
            return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)

    evidence = asyncio.run(
        check_admin_panels(BrokenControlsClient(), "https://example.com", paths=("admin/",))
    )[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] >= 1
    assert any(item["classification"] == "OBSERVED_ADMIN_LOGIN_UNVERIFIED" for item in evidence["login_pages"])
    assert evidence["baseline_available"] is False


def test_admin_finder_does_not_collapse_distinct_existing_routes_with_same_login_html():
    class TwoPanelsClient:
        config = make_config("https://example.com")

        async def get(self, url):
            path = urlsplit(url).path
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            if path in {"/admin/", "/console"}:
                return HTTPResult(url, 200, {"content-type": "text/html"}, ADMIN_LOGIN)
            return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(
        check_admin_panels(TwoPanelsClient(), "https://example.com", paths=("admin/", "console"))
    )[0].evidence
    assert evidence["candidate_count"] == 2
    assert {item["path"] for item in evidence["candidates"]} == {"/admin/", "/console"}


def test_admin_finder_filters_200_soft404_matching_multiple_404_controls():
    class Soft404Client:
        config = make_config("https://example.com")

        async def get(self, url):
            if "__stari_missing_" in url:
                return HTTPResult(url, 404, {"content-type": "text/html"}, NOT_FOUND)
            return HTTPResult(url, 200, {"content-type": "text/html"}, NOT_FOUND)

    evidence = asyncio.run(check_admin_panels(Soft404Client(), "https://example.com", paths=("console",)))[0].evidence
    assert evidence["candidate_count"] == 0
    assert evidence["login_page_count"] == 0
    assert evidence["soft_404_filtered"] == 1
