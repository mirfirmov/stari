from __future__ import annotations

from stari.core.models import Observation
from stari.engines.http_client import SafeHTTPClient

TEST_ORIGIN = "https://stari-cors-audit.invalid"


async def check_cors(client: SafeHTTPClient, base_url: str) -> list[Observation]:
    """Inspect CORS response headers using an unauthenticated, harmless GET.

    The client sends only a synthetic Origin header. It does not send credentials,
    cookies, preflight requests, or state-changing methods.
    """
    try:
        response = await client.get(base_url.rstrip("/") + "/", extra_headers={"Origin": TEST_ORIGIN})
    except Exception as exc:
        return [Observation(
            "CORS_AUDIT_ERROR", "CORS review failed", "INFO", "ERROR", base_url,
            f"{type(exc).__name__}: {str(exc)[:300]}", {"error_type": type(exc).__name__},
        )]

    headers = response.headers
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    vary_tokens = {part.strip().lower() for part in headers.get("vary", "").split(",") if part.strip()}
    evidence = {
        "http_status": response.status_code,
        "access_control_allow_origin": allow_origin or None,
        "access_control_allow_credentials": allow_credentials,
        "vary_origin": "origin" in vary_tokens,
        "test_origin": TEST_ORIGIN,
        "credentials_sent": False,
    }

    if not allow_origin:
        status, severity = "NO_CORS_ALLOW_ORIGIN", "INFO"
        details = "The response did not advertise Access-Control-Allow-Origin for the synthetic Origin request."
    elif allow_origin == "*" and allow_credentials:
        status, severity = "WILDCARD_WITH_CREDENTIALS_REJECTED_BY_BROWSERS", "INFO"
        details = "The response combines wildcard origin and credential allowance. Browsers reject wildcard ACAO for credentialed CORS, so this header pair is not by itself an exploitable credentialed read."
    elif allow_origin == TEST_ORIGIN and allow_credentials:
        status, severity = "REFLECTED_ORIGIN_WITH_CREDENTIALS", "MEDIUM"
        details = "The response reflected the synthetic Origin and allowed credentials. Confirm impact on sensitive authenticated endpoints before assigning a higher severity."
    elif allow_origin == TEST_ORIGIN:
        status, severity = "REFLECTED_ORIGIN", "MEDIUM"
        details = "The response reflected an arbitrary-looking Origin. No credentials were sent; assess the application’s data exposure and allowlist policy."
    elif allow_origin == "*":
        status, severity = "WILDCARD_PUBLIC_RESOURCE", "INFO"
        details = "The resource advertises wildcard CORS. This can be intentional for public, non-credentialed resources."
    else:
        status, severity = "CORS_ORIGIN_NOT_REFLECTED", "INFO"
        details = "The response advertises a different CORS origin; no reflection of the synthetic Origin was observed."

    if allow_origin == TEST_ORIGIN and "origin" not in vary_tokens:
        evidence["vary_header_note"] = "Origin was reflected without Vary: Origin."
    return [Observation(
        "CORS_CONFIGURATION_REVIEW", "CORS configuration review", severity, status,
        response.url, details, evidence,
    )]
