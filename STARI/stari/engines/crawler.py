from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient

MAX_PAGES = 500
MAX_SCRIPTS = 100
MAX_STORED_ITEMS = 500
_SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|passwd|session|csrf|auth|signature|api[_-]?key|"
    r"access[_-]?key|refresh[_-]?token|credential|cookie|ticket)", re.I,
)
_STATE_CHANGING_PATH = re.compile(
    r"(?:^|/)(?:logout|logoff|signout|sign-out|delete|remove|destroy|checkout|"
    r"purchase|payment|unsubscribe|reset-password|password-reset|confirm|"
    r"activate|deactivate|cart/add|order/cancel)(?:/|$)", re.I,
)
_STATE_CHANGING_ACTION = re.compile(
    r"(?:^|[_-])(?:logout|logoff|signout|delete|remove|destroy|checkout|purchase|"
    r"payment|unsubscribe|reset|confirm|activate|deactivate|cancel)(?:$|[_-])", re.I,
)
_ACTION_PARAMETER_KEYS = {"action", "do", "cmd", "command", "task", "op", "operation", "method", "event"}
_SKIP_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".csv", ".doc", ".docx", ".eot",
    ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".map", ".mov", ".mp3",
    ".mp4", ".pdf", ".png", ".ppt", ".pptx", ".rar", ".svg", ".tar",
    ".tgz", ".ttf", ".webm", ".webp", ".woff", ".woff2", ".xls",
    ".xlsx", ".zip",
}
_API_PATH = re.compile(r"/(?:api(?:/|\b)|graphql\b|rest(?:/|\b)|services?/(?:api/)?|v[0-9]+/)[A-Za-z0-9_./{}%?=&-]{0,240}", re.I)
_ABSOLUTE_URL = re.compile(r"https?://[^\s\"'<>`]+", re.I)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.meta: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self._in_title = False
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            self.links.append(values["href"].strip())
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"].strip())
        elif tag == "link" and values.get("href"):
            rel = values.get("rel", "").lower()
            if "canonical" in rel or "alternate" in rel:
                self.links.append(values["href"].strip())
        elif tag == "meta":
            name = values.get("name") or values.get("property") or ""
            content = values.get("content", "")
            if name and content:
                self.meta.append({"name": name[:100], "content": content[:300]})
        elif tag == "title":
            self._in_title = True
        elif tag == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "get").upper(),
                "fields": [],
            }
        elif tag in {"input", "select", "textarea", "button"} and self._current_form is not None:
            name = values.get("name")
            if name:
                fields = self._current_form["fields"]
                if isinstance(fields, list) and name not in fields:
                    fields.append(name[:100])

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title_parts.append(data.strip()[:200])


def _normalized_in_scope_url(candidate: str, source_url: str, client: SafeHTTPClient) -> str | None:
    if not candidate or candidate.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    absolute = urljoin(source_url, candidate.strip())
    parsed = urlsplit(absolute)
    if not is_in_scope(absolute, client.config):
        return None
    if parsed.username or parsed.password or _STATE_CHANGING_PATH.search(parsed.path):
        return None
    if parsed.path.lower().endswith(tuple(_SKIP_EXTENSIONS)):
        return None
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(
        _SENSITIVE_KEY.search(key)
        or _STATE_CHANGING_ACTION.search(key)
        or (key.casefold() in _ACTION_PARAMETER_KEYS and _STATE_CHANGING_ACTION.search(value))
        for key, value in pairs
    ):
        return None

    safe_pairs = [(key, value) for key, value in pairs if not key.lower().startswith("utm_")]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(safe_pairs), ""))


def _safe_endpoint(candidate: str, source_url: str, client: SafeHTTPClient) -> str | None:
    normalized = _normalized_in_scope_url(candidate, source_url, client)
    if not normalized:
        return None
    parsed = urlsplit(normalized)

    names = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode([(name, "") for name in names]), ""))


def _safe_url_for_storage(url: str) -> str:
    """Keep parameter names but never persist query values from crawled URLs."""
    parsed = urlsplit(url)
    query_names = [(key, "") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query_names), ""))


def _interesting_endpoint(url: str) -> bool:
    parsed = urlsplit(url)
    return bool(_API_PATH.search(parsed.path) or parsed.query)


def _extract_js_endpoints(text: str, script_url: str, client: SafeHTTPClient) -> set[str]:
    results: set[str] = set()
    for match in _API_PATH.finditer(text):
        item = _safe_endpoint(match.group(0), script_url, client)
        if item:
            results.add(item)
    for match in _ABSOLUTE_URL.finditer(text):
        item = _safe_endpoint(match.group(0).rstrip(",);"), script_url, client)
        if item and _interesting_endpoint(item):
            results.add(item)
    return results


async def check_crawler(
    client: SafeHTTPClient,
    base_url: str,
    *,
    max_pages: int = 100,
    max_scripts: int = 30,
) -> list[Observation]:
    """Crawl in-scope HTML pages using bounded GET requests only.

    Forms are inventoried but never submitted. Sensitive query parameters and
    state-changing routes are not followed or stored. JavaScript files are read
    only when hosted inside the configured scope.
    """
    max_pages = max(1, min(int(max_pages), MAX_PAGES))
    max_scripts = max(0, min(int(max_scripts), MAX_SCRIPTS))
    root = base_url.rstrip("/") + "/"
    queue: deque[str] = deque([root])
    queued = {root}
    visited: set[str] = set()
    pages: list[dict[str, object]] = []
    forms: list[dict[str, object]] = []
    script_urls: list[str] = []
    endpoints: set[str] = set()
    errors: list[dict[str, str]] = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            response = await client.get(url)
        except Exception as exc:
            errors.append({"url": url, "error": type(exc).__name__})
            continue

        content_type = response.headers.get("content-type", "").lower()
        page_record: dict[str, object] = {
            "url": _safe_url_for_storage(response.url),
            "status": response.status_code,
            "content_type": content_type[:120],
            "bytes_read": len(response.body),
            "truncated": response.truncated,
        }
        pages.append(page_record)
        if response.status_code != 200 or not ("text/html" in content_type or "application/xhtml+xml" in content_type):
            continue

        parser = _PageParser()
        try:
            parser.feed(response.text)
        except Exception as exc:
            errors.append({"url": response.url, "error": f"HTMLParser:{type(exc).__name__}"})
            continue
        page_record["title"] = " ".join(parser.title_parts)[:200]

        for item in parser.forms:
            action = str(item.get("action", ""))
            safe_action = _safe_endpoint(action or response.url, response.url, client)
            forms.append({
                "page": _safe_url_for_storage(response.url),
                "action": safe_action or "[out of scope or unsafe route]",
                "method": item.get("method", "GET"),
                "field_names": list(item.get("fields", []))[:50],
            })

        for href in parser.links:
            candidate = _normalized_in_scope_url(href, response.url, client)
            if not candidate:
                continue
            if _interesting_endpoint(candidate):
                endpoint = _safe_endpoint(candidate, response.url, client)
                if endpoint:
                    endpoints.add(endpoint)
            if candidate not in queued and len(queued) < max_pages * 10:
                queued.add(candidate)
                queue.append(candidate)

        for script in parser.scripts:
            candidate = _normalized_in_scope_url(script, response.url, client)
            if candidate and candidate not in script_urls and len(script_urls) < max_scripts:
                script_urls.append(candidate)


    for script_url in script_urls[:max_scripts]:
        try:
            response = await client.get(script_url)
        except Exception as exc:
            errors.append({"url": script_url, "error": type(exc).__name__})
            continue
        content_type = response.headers.get("content-type", "").lower()
        if response.status_code != 200:
            continue
        if not ("javascript" in content_type or urlsplit(script_url).path.lower().endswith(".js")):
            continue
        endpoints.update(_extract_js_endpoints(response.text, response.url, client))

    safe_pages = pages[:MAX_STORED_ITEMS]
    safe_forms = forms[:MAX_STORED_ITEMS]
    safe_scripts = script_urls[:MAX_STORED_ITEMS]
    safe_endpoints = sorted(endpoints)[:MAX_STORED_ITEMS]
    details = (
        f"Visited {len(pages)} page(s), found {len(forms)} form(s), "
        f"{len(script_urls)} same-scope JavaScript file(s), and {len(endpoints)} API-like endpoint(s)."
    )
    if errors:
        details += f" {len(errors)} request or parse error(s) occurred."
    return [Observation(
        "CRAWLER_INVENTORY", "Bounded web crawl and endpoint inventory", "INFO", "OBSERVED",
        base_url, details,
        {
            "max_pages": max_pages,
            "max_scripts": max_scripts,
            "pages_visited": safe_pages,
            "forms": safe_forms,
            "scripts": safe_scripts,
            "api_endpoints": safe_endpoints,
            "errors": errors[:50],
            "forms_submitted": False,
            "external_hosts_followed": False,
            "sensitive_query_values_stored": False,
            "limitations": [
                "GET requests only; HTML forms are inventoried but never submitted.",
                "Only hosts and ports in the configured project scope are crawled.",
                "No browser JavaScript execution or authenticated session is used.",
                "JavaScript analysis is static and heuristic; dynamically generated routes may be missed.",
            ],
        },
    )]
