from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urljoin

from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(xml_text: str, base_url: str, config) -> tuple[list[str], int]:
    """Return in-scope sitemap locations and count out-of-scope locations."""
    root = ET.fromstring(xml_text)
    locations: list[str] = []
    ignored = 0
    seen: set[str] = set()
    for element in root.iter():
        if _local_name(element.tag) != "loc" or not element.text:
            continue
        candidate = urljoin(base_url.rstrip("/") + "/", element.text.strip())
        if is_in_scope(candidate, config):
            if candidate not in seen:
                seen.add(candidate)
                if len(locations) < 500:
                    locations.append(candidate)
        else:
            ignored += 1
    return locations, ignored


async def check_sitemap(client: SafeHTTPClient, base_url: str) -> list[Observation]:
    url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
    try:
        response = await client.get(url)
    except Exception as exc:
        return [Observation(
            "SITEMAP_REQUEST_ERROR", "sitemap.xml request failed", "INFO", "ERROR",
            url, str(exc)[:500], {"url": url, "error_type": type(exc).__name__},
        )]

    if response.status_code != 200:
        return [Observation(
            "SITEMAP_HTTP_STATUS", "sitemap.xml response", "INFO", "OBSERVED",
            response.url, f"Server returned HTTP {response.status_code}.",
            {"requested_url": url, "final_url": response.url,
             "http_status": response.status_code,
             "content_type": response.headers.get("content-type", ""),
             "redirect_history": response.redirect_history},
        )]

    if response.truncated:
        return [Observation(
            "SITEMAP_RESPONSE_TRUNCATED", "sitemap.xml response was truncated", "LOW", "NEEDS_REVIEW",
            response.url,
            "The XML response exceeded the configured response-size limit. Increase the cap only when required and authorized.",
            {"url": response.url, "body_bytes_read": len(response.body),
             "max_response_bytes": client.config.max_response_bytes},
        )]

    try:
        locations, ignored = parse_sitemap(response.text, base_url, client.config)
    except ET.ParseError as exc:
        return [Observation(
            "SITEMAP_INVALID_XML", "sitemap.xml is not valid XML", "LOW", "NEEDS_REVIEW",
            response.url, str(exc),
            {"content_type": response.headers.get("content-type", ""),
             "body_bytes": len(response.body)},
        )]

    return [Observation(
        "SITEMAP_ANALYZED", "sitemap.xml analyzed", "INFO", "OBSERVED",
        response.url,
        f"Collected {len(locations)} unique in-scope URLs; ignored {ignored} out-of-scope URLs.",
        {"requested_url": url, "final_url": response.url,
         "http_status": response.status_code,
         "content_type": response.headers.get("content-type", ""),
         "url_count": len(locations), "ignored_out_of_scope": ignored,
         "locations": locations, "truncated": response.truncated},
    )]
