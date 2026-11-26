from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient

_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js", ".pdf", ".zip", ".woff", ".woff2")


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.mailto: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                if value.lower().startswith("mailto:"):
                    self.mailto.update(_EMAIL_RE.findall(value[7:].split("?", 1)[0]))
                else:
                    self.links.append(value.strip())


def _extract_emails(text: str) -> set[str]:
    found = {item.rstrip(".,;:!?)") for item in _EMAIL_RE.findall(text)}
    return {item for item in found if len(item) <= 254 and ".." not in item}


async def check_emails(
    client: SafeHTTPClient,
    base_url: str,
    *,
    max_pages: int = 12,
) -> list[Observation]:
    """Collect publicly published email addresses from a small same-scope page set."""
    root = base_url.rstrip("/") + "/"
    queue = [root]
    seen: set[str] = set()
    emails: set[str] = set()
    page_results: list[dict[str, object]] = []
    errors: list[str] = []

    while queue and len(seen) < max(1, min(max_pages, 20)):
        url = queue.pop(0)
        if url in seen or not is_in_scope(url, client.config):
            continue
        seen.add(url)
        try:
            response = await client.get(url)
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}")
            continue
        if response.status_code != 200 or "html" not in response.headers.get("content-type", "text/html").lower():
            continue

        body = response.text[:client.config.max_response_bytes]
        page_emails = _extract_emails(body)
        parser = _LinkExtractor()
        try:
            parser.feed(body)
        except Exception:
            pass
        page_emails.update(parser.mailto)
        emails.update(page_emails)
        page_results.append({"url": response.url, "email_count": len(page_emails), "status": response.status_code})

        for href in parser.links:
            if len(queue) + len(seen) >= max_pages * 2:
                break
            candidate = urljoin(response.url, href)
            parsed = urlsplit(candidate)
            if parsed.scheme not in {"http", "https"} or not is_in_scope(candidate, client.config):
                continue
            if parsed.path.lower().endswith(_SKIP_SUFFIXES):
                continue
            normalized = candidate.split("#", 1)[0]
            if normalized not in seen and normalized not in queue:
                queue.append(normalized)

    ordered = sorted(emails, key=str.lower)
    return [Observation(
        "PUBLIC_EMAIL_DISCOVERY", "Publicly published email addresses", "INFO",
        "FOUND" if ordered else "NONE_FOUND", base_url,
        f"Collected {len(ordered)} unique email address(es) from {len(page_results)} in-scope HTML page(s).",
        {"emails": ordered[:500], "email_count": len(ordered), "pages_scanned": page_results,
         "page_limit": max(1, min(max_pages, 20)), "errors": errors[:20],
         "source": "public page HTML and mailto links"},
    )]
