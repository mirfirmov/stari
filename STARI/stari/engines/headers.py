from __future__ import annotations

from stari.core.models import Observation
from stari.engines.http_client import SafeHTTPClient

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie"}


def _safe_header_value(name: str, value: str) -> str:
    lowered = name.lower()
    if lowered in SENSITIVE_HEADERS:
        return "[redacted]"
    if lowered == "set-cookie":
        parts = [part.strip() for part in value.split(";")]
        cookie_name = parts[0].split("=", 1)[0] if parts else "cookie"
        attributes = "; ".join(parts[1:])
        return f"{cookie_name}=<redacted>" + (f"; {attributes}" if attributes else "")
    return value[:1000]


async def check_headers(client: SafeHTTPClient, base_url: str) -> list[Observation]:
    try:
        response = await client.get(base_url)
    except Exception as exc:
        return [Observation(
            "HTTP_REQUEST_ERROR", "Root page request failed", "INFO", "ERROR",
            base_url, str(exc)[:500], {"url": base_url, "error_type": type(exc).__name__},
        )]

    headers = response.headers
    raw_items = response.header_items or list(headers.items())
    safe_items = [
        {"name": name.lower(), "value": _safe_header_value(name, value)}
        for name, value in raw_items
    ]
    observations: list[Observation] = [Observation(
        "HTTP_ROOT_RESPONSE", "Root HTTP response observed", "INFO", "OBSERVED",
        response.url,
        f"Root endpoint returned HTTP {response.status_code}; {len(safe_items)} response header(s) recorded.",
        {
            "requested_url": base_url,
            "final_url": response.url,
            "http_status": response.status_code,
            "content_type": headers.get("content-type"),
            "content_length": headers.get("content-length"),
            "server": headers.get("server"),
            "response_headers": safe_items,
            "redirect_history": response.redirect_history,
            "body_bytes_read": len(response.body),
            "body_truncated": response.truncated,
        },
    )]

    checks = [
        ("strict-transport-security", "HSTS header missing", "LOW",
         "On HTTPS sites, HSTS helps browsers enforce HTTPS after the first secure visit."),
        ("content-security-policy", "Content-Security-Policy header missing", "INFO",
         "A CSP can reduce the impact of certain content-injection issues; its absence alone is not a vulnerability."),
        ("x-content-type-options", "X-Content-Type-Options header missing", "INFO",
         "Consider sending X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy header missing", "INFO",
         "A Referrer-Policy makes referrer data handling explicit."),
        ("permissions-policy", "Permissions-Policy header missing", "INFO",
         "A Permissions-Policy can restrict browser features where appropriate."),
    ]
    for header, title, severity, details in checks:
        if header == "strict-transport-security" and not base_url.startswith("https://"):
            continue
        if header not in headers:
            observations.append(Observation(
                f"HEADER_MISSING_{header.upper().replace('-', '_')}", title,
                severity, "NEEDS_REVIEW", response.url, details,
                {"missing_header": header, "http_status": response.status_code},
            ))

    csp = headers.get("content-security-policy", "").lower()
    xfo = headers.get("x-frame-options", "").lower()
    if "frame-ancestors" not in csp and not xfo:
        observations.append(Observation(
            "CLICKJACKING_HEADERS_NOT_SEEN", "No frame restriction header detected",
            "LOW", "NEEDS_REVIEW", response.url,
            "Neither CSP frame-ancestors nor X-Frame-Options was present in the root response. Check application-specific routes before drawing conclusions.",
            {"x_frame_options_present": bool(xfo),
             "csp_frame_ancestors_present": "frame-ancestors" in csp},
        ))

    set_cookies = [value for name, value in raw_items if name.lower() == "set-cookie"]
    for index, cookie in enumerate(set_cookies, start=1):
        attributes = {
            part.strip().split("=", 1)[0].lower()
            for part in cookie.split(";")[1:]
            if part.strip()
        }
        missing = [attribute for attribute in ("httponly", "samesite") if attribute not in attributes]
        if base_url.startswith("https://") and "secure" not in attributes:
            missing.append("secure")
        if missing:
            safe_cookie = _safe_header_value("set-cookie", cookie)
            observations.append(Observation(
                "COOKIE_ATTRIBUTES_REVIEW", f"Cookie #{index} attributes need review",
                "LOW", "NEEDS_REVIEW", response.url,
                "The response cookie appears to omit one or more common attributes.",
                {"cookie_index": index,
                 "possibly_missing_attributes": missing,
                 "cookie_name_and_attributes": safe_cookie},
            ))

    server_header = headers.get("server")
    if server_header:
        observations.append(Observation(
            "SERVER_HEADER_PRESENT", "Server response header disclosed", "INFO", "OBSERVED",
            response.url, "The server header is present; its value is recorded as an observation, not a vulnerability.",
            {"server": server_header[:200]},
        ))

    return observations
