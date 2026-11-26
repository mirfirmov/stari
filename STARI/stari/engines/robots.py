from __future__ import annotations

from urllib.parse import urljoin

from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient


def parse_robots(text: str) -> dict[str, list[str]]:
    """Extract commonly used robots.txt directives without treating them as ACLs."""
    result = {
        "user_agent": [],
        "disallow": [],
        "allow": [],
        "sitemap": [],
        "crawl_delay": [],
        "host": [],
    }
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key in result and value:
            result[key].append(value)
    return result


async def check_robots(client: SafeHTTPClient, base_url: str) -> list[Observation]:
    url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    try:
        response = await client.get(url)
    except Exception as exc:
        return [Observation(
            "ROBOTS_REQUEST_ERROR", "robots.txt request failed", "INFO", "ERROR",
            url, str(exc)[:500], {"url": url, "error_type": type(exc).__name__},
        )]

    location = response.headers.get("location")
    redirect_note = ""
    if response.status_code in {301, 302, 303, 307, 308} and location:
        destination = urljoin(response.url, location)
        redirect_note = (
            f" Redirect destination {destination} is outside the configured scope; "
            "STARI did not request it. Add that host to allowed_hosts only if it is "
            "part of your authorized assessment."
        )

    if response.status_code != 200:
        return [Observation(
            "ROBOTS_HTTP_STATUS", "robots.txt response", "INFO", "OBSERVED",
            response.url,
            f"Server returned HTTP {response.status_code}.{redirect_note}",
            {
                "requested_url": url,
                "final_url": response.url,
                "http_status": response.status_code,
                "location": location,
                "redirect_history": response.redirect_history,
                "content_type": response.headers.get("content-type", ""),
                "body_bytes": len(response.body),
                "body_truncated": response.truncated,
            },
        )]

    content = response.text.lstrip("\ufeff")
    parsed = parse_robots(content)
    same_scope_sitemaps = [
        item for item in parsed["sitemap"]
        if is_in_scope(urljoin(base_url.rstrip("/") + "/", item), client.config)
    ]
    total_paths = len(parsed["disallow"]) + len(parsed["allow"])
    details = (
        f"HTTP 200. Parsed {total_paths} Allow/Disallow entries, "
        f"{len(same_scope_sitemaps)} in-scope Sitemap entries and "
        f"{len(parsed['user_agent'])} User-agent group marker(s). "
        "Robots directives are crawler hints, not access controls."
    )
    if response.truncated:
        details += " Response body reached the configured byte limit."

    evidence = {
        "requested_url": url,
        "final_url": response.url,
        "http_status": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "body_bytes": len(response.body),
        "content": content,
        **{key: values[:500] for key, values in parsed.items()},
        "sitemaps_in_scope": same_scope_sitemaps[:100],
        "redirect_history": response.redirect_history,
        "truncated": response.truncated,
    }
    return [Observation(
        "ROBOTS_DISCOVERED", "robots.txt analyzed", "INFO", "OBSERVED",
        response.url, details, evidence,
    )]
