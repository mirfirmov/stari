from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import time
from typing import Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from stari.core.config import ProjectConfig
from stari.core.models import Observation



SOURCE_NAMES: tuple[str, ...] = (
    "crtsh",
    "certspotter",
    "hackertarget",
    "otx",
    "urlscan",
    "wayback",
)
DEFAULT_RESULT_LIMIT = 500
MAX_RESULT_LIMIT = 5_000
MAX_SOURCE_RESPONSE_BYTES = 4 * 1024 * 1024


def _is_subdomain(hostname: str, domain: str) -> bool:
    host = hostname.lower().rstrip(".")
    root = domain.lower().rstrip(".")
    return host != root and host.endswith("." + root)


def _normalize_hostname(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or "*" in candidate or any(ch in candidate for ch in "/:@?#"):
        return None
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    ):
        return None
    return ascii_name


def _host_from_url(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw if "://" in raw else "//" + raw)
        return _normalize_hostname(parsed.hostname or "")
    except ValueError:
        return None


def _add_name(names: set[str], value: object, domain: str) -> None:
    if not isinstance(value, str):
        return
    normalized = _normalize_hostname(value)
    if normalized and _is_subdomain(normalized, domain):
        names.add(normalized)


def _parse_crtsh(payload: object, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            raw = entry.get(key)
            if isinstance(raw, str):
                for candidate in raw.splitlines():
                    _add_name(names, candidate, domain)
    return names


def _parse_certspotter(payload: object, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for candidate in entry.get("dns_names", []) if isinstance(entry.get("dns_names"), list) else []:
            _add_name(names, candidate, domain)
    return names


def _parse_hackertarget(payload: str, domain: str) -> set[str]:
    names: set[str] = set()
    for row in csv.reader(io.StringIO(payload)):
        if not row:
            continue
        _add_name(names, row[0], domain)
    return names


def _parse_otx(payload: object, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, dict):
        return names
    records = payload.get("passive_dns", [])
    if not isinstance(records, list):
        return names
    for record in records:
        if isinstance(record, dict):
            for key in ("hostname", "domain", "rrname"):
                _add_name(names, record.get(key), domain)
    return names


def _parse_urlscan(payload: object, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, dict):
        return names
    results = payload.get("results", [])
    if not isinstance(results, list):
        return names
    for result in results:
        if not isinstance(result, dict):
            continue
        for section in ("page", "task"):
            detail = result.get(section)
            if not isinstance(detail, dict):
                continue
            _add_name(names, detail.get("domain"), domain)
            for key in ("url", "source", "redirected"):
                host = _host_from_url(str(detail.get(key) or ""))
                if host:
                    _add_name(names, host, domain)
    return names


def _parse_wayback(payload: object, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, list):
        return names

    for row in payload:
        if isinstance(row, list):
            if row and isinstance(row[0], str) and row[0].lower() == "original":
                continue
            if row:
                host = _host_from_url(str(row[0]))
                if host:
                    _add_name(names, host, domain)
        elif isinstance(row, str):
            host = _host_from_url(row)
            if host:
                _add_name(names, host, domain)
    return names


async def _bounded_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: list[tuple[str, str]] | dict[str, str] | None = None,
    max_bytes: int = MAX_SOURCE_RESPONSE_BYTES,
) -> tuple[bytes | None, str | None]:
    try:
        async with client.stream("GET", url, params=params) as response:
            if response.status_code != 200:
                return None, f"HTTP {response.status_code}"
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                return None, f"response exceeds {max_bytes} bytes"
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > max_bytes:
                    return None, f"response exceeds {max_bytes} bytes"
                body.extend(chunk)
            return bytes(body), None
    except (httpx.HTTPError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


async def _fetch_crtsh(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"}, max_bytes=max_bytes,
    )
    if error:
        return set(), error
    try:
        return _parse_crtsh(json.loads((body or b"").decode("utf-8", errors="replace")), domain), None
    except (json.JSONDecodeError, UnicodeError) as exc:
        return set(), f"invalid JSON: {type(exc).__name__}"


async def _fetch_certspotter(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, "https://api.certspotter.com/v1/issuances",
        params=[("domain", domain), ("include_subdomains", "true"), ("expand", "dns_names")],
        max_bytes=max_bytes,
    )
    if error:
        return set(), error
    try:
        return _parse_certspotter(json.loads((body or b"").decode("utf-8", errors="replace")), domain), None
    except (json.JSONDecodeError, UnicodeError) as exc:
        return set(), f"invalid JSON: {type(exc).__name__}"


async def _fetch_hackertarget(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, "https://api.hackertarget.com/hostsearch/",
        params={"q": domain}, max_bytes=max_bytes,
    )
    if error:
        return set(), error
    text = (body or b"").decode("utf-8", errors="replace")
    if text.lstrip().upper().startswith(("ERROR", "API COUNT", "PLEASE")):
        return set(), text.strip()[:180]
    return _parse_hackertarget(text, domain), None


async def _fetch_otx(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        max_bytes=max_bytes,
    )
    if error:
        return set(), error
    try:
        return _parse_otx(json.loads((body or b"").decode("utf-8", errors="replace")), domain), None
    except (json.JSONDecodeError, UnicodeError) as exc:
        return set(), f"invalid JSON: {type(exc).__name__}"


async def _fetch_urlscan(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, "https://urlscan.io/api/v1/search/",
        params={"q": f"domain:{domain}", "size": "100"}, max_bytes=max_bytes,
    )
    if error:
        return set(), error
    try:
        return _parse_urlscan(json.loads((body or b"").decode("utf-8", errors="replace")), domain), None
    except (json.JSONDecodeError, UnicodeError) as exc:
        return set(), f"invalid JSON: {type(exc).__name__}"


async def _fetch_wayback(client: httpx.AsyncClient, domain: str, max_bytes: int) -> tuple[set[str], str | None]:
    body, error = await _bounded_get(
        client, "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"{domain}/", "matchType": "domain", "output": "json",
            "fl": "original", "collapse": "urlkey", "filter": "statuscode:200",
            "limit": "1000",
        },
        max_bytes=max_bytes,
    )
    if error:
        return set(), error
    try:
        return _parse_wayback(json.loads((body or b"").decode("utf-8", errors="replace")), domain), None
    except (json.JSONDecodeError, UnicodeError) as exc:
        return set(), f"invalid JSON: {type(exc).__name__}"


Provider = Callable[[httpx.AsyncClient, str, int], Awaitable[tuple[set[str], str | None]]]
SOURCE_FETCHERS: dict[str, Provider] = {
    "crtsh": _fetch_crtsh,
    "certspotter": _fetch_certspotter,
    "hackertarget": _fetch_hackertarget,
    "otx": _fetch_otx,
    "urlscan": _fetch_urlscan,
    "wayback": _fetch_wayback,
}


async def check_subdomains(
    config: ProjectConfig,
    *,
    result_limit: int = DEFAULT_RESULT_LIMIT,
    selected_sources: list[str] | tuple[str, ...] | None = None,
    fetchers: dict[str, Provider] | None = None,
) -> list[Observation]:
    """Discover subdomains passively from public indexes; never resolve candidates.

    Only external index APIs are contacted. This function sends no DNS queries
    for candidate names and makes no HTTP/TCP connections to the target domain
    or discovered subdomains.
    """
    base_host = (urlsplit(config.base_url).hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if not base_host:
        return [Observation(
            "SUBDOMAIN_DISCOVERY", "Passive subdomain discovery", "INFO", "ERROR",
            config.base_url, "Target hostname is unavailable.", {},
        )]
    try:
        ipaddress.ip_address(base_host)
        return [Observation(
            "SUBDOMAIN_DISCOVERY", "Passive subdomain discovery", "INFO", "ERROR",
            config.base_url, "Subdomain discovery requires a DNS domain, not an IP address.",
            {"base_domain": base_host, "reason": "target_is_ip_address"},
        )]
    except ValueError:
        pass

    result_limit = max(1, min(int(result_limit), MAX_RESULT_LIMIT))
    providers = fetchers or SOURCE_FETCHERS
    names_to_query = list(dict.fromkeys(selected_sources or SOURCE_NAMES))
    invalid_sources = [name for name in names_to_query if name not in providers]
    names_to_query = [name for name in names_to_query if name in providers]
    if not names_to_query:
        return [Observation(
            "SUBDOMAIN_DISCOVERY", "Passive subdomain discovery", "INFO", "ERROR",
            config.base_url, "No valid passive sources were selected.",
            {"base_domain": base_host, "available_sources": list(providers), "invalid_sources": invalid_sources},
        )]

    timeout = min(max(float(config.request_timeout_seconds), 3.0), 20.0)
    headers = {
        "User-Agent": config.user_agent,
        "Accept": "application/json, text/plain, */*",
    }
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    interval = 1.0 / max(float(config.requests_per_second), 0.1)
    last_request = 0.0
    pace_lock = asyncio.Lock()

    async def pace() -> None:
        nonlocal last_request
        async with pace_lock:
            delay = interval - (time.monotonic() - last_request)
            if last_request and delay > 0:
                await asyncio.sleep(delay)
            last_request = time.monotonic()

    source_results: dict[str, dict[str, object]] = {}
    aggregate: dict[str, set[str]] = {}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers=headers,
        limits=limits,
    ) as client:
        async def run_source(source_name: str) -> tuple[str, set[str], str | None]:
            await pace()
            try:
                names, error = await providers[source_name](
                    client, base_host, MAX_SOURCE_RESPONSE_BYTES
                )
                filtered = {
                    name for raw in names
                    if (name := _normalize_hostname(raw)) and _is_subdomain(name, base_host)
                }
                return source_name, filtered, error
            except Exception as exc:
                return source_name, set(), f"{type(exc).__name__}: {exc}"

        results = await asyncio.gather(*(run_source(name) for name in names_to_query))

    for source_name, names, error in results:
        status = "ERROR" if error else ("FOUND" if names else "EMPTY")
        source_results[source_name] = {
            "status": status,
            "count": len(names),
            "error": error,
        }
        for hostname in names:
            aggregate.setdefault(hostname, set()).add(source_name)

    discovered = [
        {"hostname": hostname, "sources": sorted(aggregate[hostname])}
        for hostname in sorted(aggregate)
    ]
    total_discovered = len(discovered)
    displayed = discovered[:result_limit]
    source_successes = sum(1 for item in source_results.values() if item["status"] != "ERROR")
    status = "FOUND" if displayed else ("SOURCE_ERRORS" if source_successes == 0 else "NO_MATCH")
    details = (
        f"Found {total_discovered} unique subdomain(s) in public indexes; "
        f"showing {len(displayed)}. Queried {len(names_to_query)} passive source(s). "
        "No DNS resolution, wordlist guessing, or HTTP/TCP probes were performed against the target."
    )
    if invalid_sources:
        details += f" Ignored unknown source(s): {', '.join(invalid_sources)}."
    error_count = sum(1 for item in source_results.values() if item["status"] == "ERROR")
    if error_count:
        details += f" {error_count} source(s) failed or were rate-limited."

    return [Observation(
        "SUBDOMAIN_DISCOVERY", "Passive subdomain discovery", "INFO", status,
        config.base_url, details,
        {
            "base_domain": base_host,
            "mode": "passive_osint",
            "source_results": source_results,
            "source_count": len(names_to_query),
            "successful_source_count": source_successes,
            "failed_source_count": error_count,
            "total_discovered": total_discovered,
            "display_limit": result_limit,
            "subdomains": displayed,
            "all_subdomains": discovered,
            "dns_queries_to_candidates": 0,
            "target_http_requests": 0,
            "target_tcp_connections": 0,
            "wordlist_bruteforce": False,
            "results_may_be_historical": True,
            "invalid_sources": invalid_sources,
        },
    )]
