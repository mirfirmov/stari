from __future__ import annotations

import re
import secrets
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient

MAX_ENDPOINTS = 8
MAX_PARAMETERS = 10
MAX_SQLI_PARAMETERS = 3

_SENSITIVE_PARAMETER = re.compile(
    r"(?:token|secret|password|passwd|session|csrf|auth|signature|api[_-]?key|access[_-]?key|"
    r"refresh[_-]?token|reset|verify|code|credential|cookie)",
    re.IGNORECASE,
)
_STATEFUL_PATH = re.compile(
    r"(?:logout|logoff|delete|remove|destroy|checkout|purchase|payment|unsubscribe|"
    r"reset-password|password-reset|confirm|activate|update-profile)",
    re.IGNORECASE,
)
_STATEFUL_ACTION = re.compile(
    r"(?:^|[_-])(?:logout|logoff|signout|delete|remove|destroy|checkout|purchase|"
    r"payment|unsubscribe|reset|confirm|activate|deactivate|cancel)(?:$|[_-])", re.I,
)
_ACTION_PARAMETER_KEYS = {"action", "do", "cmd", "command", "task", "op", "operation", "method", "event"}
_SQL_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"you have an error in your sql syntax|mysqli?[_ ](?:fetch|query|error)|mysql_fetch", re.I)),
    ("postgresql", re.compile(r"postgresql.*(?:error|exception)|pg_query\(\)|unterminated quoted string", re.I)),
    ("sqlite", re.compile(r"sqlite(?:3)?\.(?:operational|database)error|sqlite error:|near \"[^\"]+\": syntax error", re.I)),
    ("mssql", re.compile(r"unclosed quotation mark after the character string|\[sql server\]|odbc sql server driver", re.I)),
    ("oracle", re.compile(r"ora-\d{5}", re.I)),
    ("generic_sqlstate", re.compile(r"sqlstate\[[0-9a-z]+\]", re.I)),
)


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.hrefs.append(value.strip())


def _safe_display_url(url: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_query = urlencode([(key, "[redacted]") for key, _ in pairs])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, redacted_query, ""))


def _valid_candidate(url: str, client: SafeHTTPClient) -> bool:
    if not is_in_scope(url, client.config):
        return False
    parsed = urlsplit(url)
    if not parsed.query or _STATEFUL_PATH.search(parsed.path):
        return False
    if parsed.path.lower().endswith((
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
        ".pdf", ".zip", ".xml", ".json", ".woff", ".woff2", ".ico",
    )):
        return False
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(
        _STATEFUL_ACTION.search(key)
        or (key.casefold() in _ACTION_PARAMETER_KEYS and _STATEFUL_ACTION.search(value))
        for key, value in pairs
    ):
        return False
    return any(key and not _SENSITIVE_PARAMETER.search(key) for key, _ in pairs)


async def discover_parameterized_urls(
    client: SafeHTTPClient,
    base_url: str,
    *,
    limit: int = MAX_ENDPOINTS,
) -> list[str]:
    """Collect GET URLs with query parameters from the homepage and sitemap."""
    root = base_url.rstrip("/") + "/"
    candidates: list[str] = []

    def add_candidate(candidate: str) -> None:
        normalized = urlunsplit((*urlsplit(candidate)[:4], ""))
        if _valid_candidate(normalized, client) and normalized not in candidates:
            candidates.append(normalized)

    try:
        homepage = await client.get(root)
        if homepage.status_code == 200 and "html" in homepage.headers.get("content-type", "text/html").lower():
            page_url = homepage.url
            if urlsplit(page_url).query:
                add_candidate(page_url)
            parser = _AnchorParser()
            parser.feed(homepage.text)
            for href in parser.hrefs:
                add_candidate(urljoin(page_url, href))
    except Exception:
        pass



    try:
        sitemap_url = urljoin(root, "sitemap.xml")
        sitemap = await client.get(sitemap_url)
        if sitemap.status_code == 200 and "xml" in sitemap.headers.get("content-type", "application/xml").lower():
            for match in re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap.text, re.I | re.S):
                add_candidate(match.strip())
    except Exception:
        pass

    return candidates[:max(1, min(limit, MAX_ENDPOINTS))]


def _replace_parameter(url: str, index: int, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if index < 0 or index >= len(pairs):
        raise IndexError("Query parameter index is out of range.")
    pairs[index] = (pairs[index][0], value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))


def _fingerprint(text: str) -> str:

    normalized = re.sub(r"\s+", " ", text[:12000]).strip()
    normalized = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", normalized, flags=re.I)
    normalized = re.sub(r"\b\d{10,}\b", "<number>", normalized)
    return normalized


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, _fingerprint(left), _fingerprint(right), autojunk=False).ratio()


def _matched_sql_errors(text: str) -> list[str]:
    return [name for name, pattern in _SQL_ERROR_PATTERNS if pattern.search(text)]


def _parameter_indices(url: str, cap: int) -> list[int]:
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return [
        index for index, (name, _value) in enumerate(pairs)
        if name and not _SENSITIVE_PARAMETER.search(name)
    ][:cap]


async def check_xss_reflection(
    client: SafeHTTPClient,
    base_url: str,
    *,
    max_parameters: int = MAX_PARAMETERS,
) -> list[Observation]:
    """Run non-executable reflected HTML canary checks on in-scope GET parameters.

    No JavaScript, event handlers, cookies, or browser execution are used. A raw
    canary indicates an unsafe reflection surface, not confirmed executable XSS.
    """
    urls = await discover_parameterized_urls(client, base_url)
    tested: list[dict[str, object]] = []
    errors: list[str] = []
    probes_sent = 0

    for url in urls:
        if probes_sent >= max_parameters:
            break
        try:
            baseline = await client.get(url)
        except Exception as exc:
            errors.append(type(exc).__name__)
            continue
        indices = _parameter_indices(url, max_parameters - probes_sent)
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for index in indices:
            if probes_sent >= max_parameters:
                break
            nonce = secrets.token_hex(5)
            canary = f'<stari-probe data-stari="{nonce}">stari</stari-probe>'
            probe_value = (pairs[index][1] + " " + canary).strip()
            probe_url = _replace_parameter(url, index, probe_value)
            probes_sent += 1
            try:
                response = await client.get(probe_url)
            except Exception as exc:
                errors.append(type(exc).__name__)
                continue

            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type and "xhtml" not in content_type:
                continue
            raw_reflection = canary in response.text
            escaped_reflection = (
                nonce in response.text
                and not raw_reflection
                and ("&lt;stari-probe" in response.text.lower() or "&#" in response.text)
            )
            if raw_reflection or escaped_reflection:
                tested.append({
                    "endpoint": _safe_display_url(url),
                    "parameter": pairs[index][0],
                    "classification": "UNESCAPED_HTML_REFLECTION" if raw_reflection else "HTML_ESCAPED_REFLECTION",
                    "http_status": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "response_length": len(response.body),
                    "baseline_status": baseline.status_code,
                    "javascript_executed": False,
                })

    unescaped = [item for item in tested if item["classification"] == "UNESCAPED_HTML_REFLECTION"]
    escaped = [item for item in tested if item["classification"] == "HTML_ESCAPED_REFLECTION"]
    if unescaped:
        status, severity = "NEEDS_REVIEW", "MEDIUM"
        details = (
            f"Found {len(unescaped)} parameter(s) reflecting a harmless HTML canary without escaping. "
            "This is a potential XSS surface, not proof of JavaScript execution. Manual context validation is required."
        )
    elif escaped:
        status, severity = "REFLECTION_ESCAPED", "INFO"
        details = f"Input was reflected with HTML escaping in {len(escaped)} parameter(s); no unescaped canary was observed."
    else:
        status, severity = ("NO_CANDIDATE_URLS", "INFO") if not urls else ("NO_UNESCAPED_REFLECTION", "INFO")
        details = (
            "No in-scope GET URLs with testable query parameters were discovered."
            if not urls else f"Tested {probes_sent} parameter(s); no unescaped HTML canary reflection was observed."
        )
    if errors:
        details += f" {len(errors)} request(s) failed."

    return [Observation(
        "XSS_REFLECTION_CHECK", "Reflected XSS surface check", severity, status,
        base_url, details,
        {
            "tested_urls": len(urls),
            "probes_sent": probes_sent,
            "max_probe_budget": max_parameters,
            "results": tested,
            "request_errors": errors[:20],
            "probe_type": "non-executable custom HTML element canary",
            "javascript_execution": False,
            "limitation": "Does not test DOM XSS, POST forms, script execution, or authenticated-only pages.",
        },
    )]


async def check_sqli_boolean_and_error(
    client: SafeHTTPClient,
    base_url: str,
    *,
    max_parameters: int = MAX_SQLI_PARAMETERS,
) -> list[Observation]:
    """Run bounded GET-only SQLi heuristics (quote-error + boolean differential).

    No time delays, stacked statements, writes, authentication attempts, or POSTs.
    Results are potential indicators and are never marked as confirmed.
    """
    urls = await discover_parameterized_urls(client, base_url)
    findings: list[dict[str, object]] = []
    errors: list[str] = []
    params_tested = 0
    probes_sent = 0

    for url in urls:
        if params_tested >= max_parameters:
            break
        try:
            baseline = await client.get(url)
        except Exception as exc:
            errors.append(type(exc).__name__)
            continue
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        for index in _parameter_indices(url, max_parameters - params_tested):
            if params_tested >= max_parameters:
                break
            params_tested += 1
            name, original = pairs[index]
            numeric = original.strip().isdigit()
            if numeric:
                true_value = f"{original} AND 1=1"
                false_value = f"{original} AND 1=2"
            else:
                true_value = f"{original}' AND '1'='1"
                false_value = f"{original}' AND '1'='2"

            parameter_result: dict[str, object] = {
                "endpoint": _safe_display_url(url),
                "parameter": name,
                "parameter_kind": "numeric-like" if numeric else "string-like",
                "baseline_status": baseline.status_code,
                "signals": [],
            }


            quote_url = _replace_parameter(url, index, original + "'")
            true_url = _replace_parameter(url, index, true_value)
            false_url = _replace_parameter(url, index, false_value)
            probe_responses = []
            for probe_url in (quote_url, true_url, false_url):
                probes_sent += 1
                try:
                    probe_responses.append(await client.get(probe_url))
                except Exception as exc:
                    errors.append(type(exc).__name__)
                    probe_responses.append(None)

            quote_response, true_response, false_response = probe_responses
            if quote_response is not None:
                baseline_errors = set(_matched_sql_errors(baseline.text))
                quote_errors = set(_matched_sql_errors(quote_response.text)) - baseline_errors
                if quote_errors:
                    parameter_result["signals"].append("DATABASE_ERROR_SIGNATURE")
                    parameter_result["database_error_families"] = sorted(quote_errors)

            if true_response is not None and false_response is not None:
                true_similarity = _similarity(baseline.text, true_response.text)
                false_similarity = _similarity(baseline.text, false_response.text)
                true_false_similarity = _similarity(true_response.text, false_response.text)
                parameter_result["true_similarity_to_baseline"] = round(true_similarity, 4)
                parameter_result["false_similarity_to_baseline"] = round(false_similarity, 4)
                parameter_result["true_false_similarity"] = round(true_false_similarity, 4)
                same_status = true_response.status_code == baseline.status_code
                different_false = (
                    false_response.status_code != baseline.status_code
                    or false_similarity < 0.78
                    or true_false_similarity < 0.78
                )
                if same_status and true_similarity >= 0.92 and different_false:
                    parameter_result["signals"].append("BOOLEAN_RESPONSE_DIFFERENTIAL")

            if parameter_result["signals"]:
                parameter_result["classification"] = "POTENTIAL_SQLI"
                findings.append(parameter_result)

    if findings:
        status, severity = "NEEDS_REVIEW", "MEDIUM"
        details = (
            f"Observed SQL-related error or boolean-response differential on {len(findings)} parameter(s). "
            "This is heuristic evidence, not confirmation of SQL injection."
        )
    elif params_tested == 0:
        status, severity = "NO_CANDIDATE_PARAMETERS", "INFO"
        details = "No in-scope GET query parameters were discovered for testing."
    else:
        status, severity = "NO_SQLI_SIGNAL", "INFO"
        details = f"Tested {params_tested} parameter(s); no SQL error or boolean-differential signal was observed."
    if errors:
        details += f" {len(errors)} request(s) failed."

    return [Observation(
        "SQLI_HEURISTIC_CHECK", "SQL injection heuristic check", severity, status,
        base_url, details,
        {
            "parameter_count_tested": params_tested,
            "probe_requests_sent": probes_sent,
            "max_parameter_budget": max_parameters,
            "findings": findings,
            "request_errors": errors[:20],
            "probe_methods": ["single-quote error signature", "paired boolean comparison"],
            "time_based_probes": False,
            "stacked_queries": False,
            "state_changing_methods": False,
            "limitation": "GET query parameters only; dynamic pages can cause false positives or false negatives.",
        },
    )]
