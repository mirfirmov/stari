from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from typing import Any
from urllib.parse import quote

import dns.exception
import dns.resolver
import httpx

from stari.core.models import Observation

WHOIS_IANA_SERVER = "whois.iana.org"
RDAP_BOOTSTRAP_URL = "https://rdap.org"
MAX_IP_LOOKUPS = 8
WHOIS_RESPONSE_LIMIT = 262_144

_DOMAIN_FIELDS = {
    "domain_name": "Domain Name",
    "registry_domain_id": "Registry Domain ID",
    "registrar": "Registrar",
    "registrar_whois_server": "Registrar WHOIS Server",
    "registrar_url": "Registrar URL",
    "updated_date": "Updated Date",
    "creation_date": "Creation Date",
    "registry_expiry_date": "Registry Expiry Date",
    "expiration_date": "Expiration Date",
    "domain_status": "Domain Status",
    "name_server": "Name Server",
    "dnssec": "DNSSEC",
}

_IP_FIELDS = {
    "net_range": "NetRange",
    "cidr": "CIDR",
    "net_name": "NetName",
    "net_handle": "NetHandle",
    "parent": "Parent",
    "net_type": "NetType",
    "organization": "Organization",
    "org_name": "OrgName",
    "country": "Country",
    "reg_date": "RegDate",
    "updated": "Updated",
    "origin_as": "OriginAS",
}

_FIELD_MAPS = {"domain": _DOMAIN_FIELDS, "ip": _IP_FIELDS}


class WhoisLookupError(RuntimeError):
    """A registry lookup failed or returned no usable registration data."""


class _RequestPacer:
    """Apply the project's request-rate ceiling to registry lookups."""

    def __init__(self, requests_per_second: float):
        self.interval = 1.0 / max(float(requests_per_second), 0.1)
        self.last_request: float | None = None

    def wait(self) -> None:
        now = time.monotonic()
        if self.last_request is not None:
            delay = self.interval - (now - self.last_request)
            if delay > 0:
                time.sleep(delay)
        self.last_request = time.monotonic()


def _whois_query(
    server: str, query: str, timeout: float, max_bytes: int,
    pacer: _RequestPacer | None = None,
) -> str:
    """Query a WHOIS server on TCP/43, with a strict response size cap."""
    host = server.strip().lower().removeprefix("whois://").rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        raise WhoisLookupError(f"Invalid WHOIS server referral: {server!r}")
    if pacer is not None:
        pacer.wait()
    payload = query.encode("idna") + b"\r\n"
    chunks: list[bytes] = []
    received = 0
    with socket.create_connection((host, 43), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(payload)
        while received < max_bytes:
            chunk = connection.recv(min(8192, max_bytes - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
    if not chunks:
        raise WhoisLookupError(f"WHOIS server {host} returned an empty response.")
    return b"".join(chunks).decode("utf-8", errors="replace")


def _extract_whois_referral(text: str) -> str | None:
    patterns = (
        r"(?im)^\s*refer\s*:\s*(?:whois://)?([a-z0-9.-]+)",
        r"(?im)^\s*whois\s*:\s*(?:whois://)?([a-z0-9.-]+)",
        r"(?im)^\s*referralserver\s*:\s*whois://([a-z0-9.-]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            candidate = match.group(1).strip().rstrip(".")
            if candidate and candidate != WHOIS_IANA_SERVER:
                return candidate
    return None


def _parse_whois_fields(text: str, kind: str) -> dict[str, list[str]]:
    """Extract a small allowlist of registry fields; omit contact PII."""
    allowed = _FIELD_MAPS[kind]
    normalized_to_key = {
        re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_"): key
        for key, label in allowed.items()
    }
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith( ("%", "#", ";")):
            continue
        if ":" not in line:
            continue
        label, value = line.split(":", 1)
        normalized = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")
        key = normalized_to_key.get(normalized)
        cleaned = value.strip()
        if key and cleaned:
            bucket = values.setdefault(key, [])
            if cleaned not in bucket and len(bucket) < 12:
                bucket.append(cleaned[:500])
    return values


def _vcard_value(entity: dict[str, Any], property_name: str) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and str(item[0]).lower() == property_name:
            value = item[3]
            if isinstance(value, str) and value.strip():
                return value.strip()[:300]
    return None


def _summarize_rdap(data: dict[str, Any], kind: str) -> dict[str, Any]:
    """Keep useful registration metadata while excluding personal contact data."""
    if kind == "domain":
        entities = data.get("entities") or []
        registrar = None
        for entity in entities:
            if "registrar" in [str(role).lower() for role in entity.get("roles", [])]:
                registrar = _vcard_value(entity, "fn") or entity.get("handle")
                if registrar:
                    break
        events: dict[str, str] = {}
        for event in data.get("events") or []:
            action = str(event.get("eventAction", "")).lower()
            date = event.get("eventDate")
            if action and date:
                events[action] = str(date)
        return {
            "domain_name": data.get("ldhName") or data.get("unicodeName"),
            "registry_domain_id": data.get("handle"),
            "registrar": registrar,
            "domain_status": [str(value) for value in data.get("status", [])],
            "name_server": [
                str(item.get("ldhName") or item.get("unicodeName"))
                for item in data.get("nameservers", [])
                if item.get("ldhName") or item.get("unicodeName")
            ],
            "events": events,
        }

    entities = data.get("entities") or []
    organization = None
    for entity in entities:
        roles = [str(role).lower() for role in entity.get("roles", [])]
        if any(role in roles for role in ("registrant", "technical", "administrative")):
            organization = _vcard_value(entity, "org")
            if organization:
                break
    return {
        "network_name": data.get("name"),
        "network_handle": data.get("handle"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "country": data.get("country"),
        "network_type": data.get("type"),
        "parent_handle": data.get("parentHandle"),
        "organization": organization,
        "network_status": [str(value) for value in data.get("status", [])],
    }


def _rdap_lookup(
    kind: str,
    query: str,
    *,
    timeout: float,
    max_bytes: int,
    user_agent: str,
    pacer: _RequestPacer | None = None,
) -> dict[str, Any]:
    url = f"{RDAP_BOOTSTRAP_URL}/{kind}/{quote(query, safe=':.')}"
    headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": user_agent[:200],
    }
    chunks: list[bytes] = []
    size = 0
    if pacer is not None:
        pacer.wait()
    with httpx.stream(
        "GET", url, headers=headers, timeout=timeout, follow_redirects=True,
    ) as response:
        if response.status_code >= 400:
            raise WhoisLookupError(f"RDAP returned HTTP {response.status_code} for {query}.")
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise WhoisLookupError(f"RDAP response exceeded {max_bytes} bytes.")
            chunks.append(chunk)
    try:
        data = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WhoisLookupError("RDAP returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise WhoisLookupError("RDAP returned an unexpected JSON document.")
    summary = _summarize_rdap(data, kind)
    if not any(value for value in summary.values()):
        raise WhoisLookupError(f"RDAP returned no usable {kind} registration fields.")
    return summary


def _lookup_registration(
    query: str,
    kind: str,
    *,
    timeout: float,
    max_bytes: int,
    user_agent: str,
    pacer: _RequestPacer | None = None,
) -> dict[str, Any]:
    """Use RDAP first, then classic WHOIS for registries without usable RDAP."""
    rdap_errors: list[str] = []
    try:
        fields = _rdap_lookup(
            kind, query, timeout=timeout, max_bytes=max_bytes,
            user_agent=user_agent, pacer=pacer,
        )
        return {
            "source": "RDAP",
            "registry_server": None,
            "fields": fields,
        }
    except (httpx.HTTPError, OSError, TimeoutError, WhoisLookupError, ValueError) as exc:
        rdap_errors.append(f"RDAP: {type(exc).__name__}: {str(exc)[:180]}")

    try:
        iana_response = _whois_query(
            WHOIS_IANA_SERVER, query, timeout,
            min(max_bytes, WHOIS_RESPONSE_LIMIT), pacer,
        )
        referral = _extract_whois_referral(iana_response)
        if referral:
            registry_response = _whois_query(
                referral, query, timeout,
                min(max_bytes, WHOIS_RESPONSE_LIMIT), pacer,
            )
            fields = _parse_whois_fields(registry_response, kind)
            if fields:
                return {
                    "source": "WHOIS",
                    "registry_server": referral,
                    "fields": fields,
                    "fallback_reason": "; ".join(rdap_errors),
                }
            rdap_errors.append(f"{referral} returned no recognized WHOIS fields")
        else:
            rdap_errors.append("IANA did not return a WHOIS referral")
    except (OSError, TimeoutError, WhoisLookupError, UnicodeError) as exc:
        rdap_errors.append(f"WHOIS: {type(exc).__name__}: {str(exc)[:180]}")

    raise WhoisLookupError("; ".join(rdap_errors))


def _resolve_host_addresses(hostname: str, timeout: float) -> tuple[list[str], list[str]]:
    """Resolve A and AAAA answers, preserving resolver errors separately."""
    try:
        literal = ipaddress.ip_address(hostname)
        return [str(literal)], []
    except ValueError:
        pass

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(max(timeout, 0.5), 4.0)
    addresses: list[str] = []
    errors: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(
                hostname, record_type,
                lifetime=min(max(timeout, 0.5), 4.0),
                search=False,
                raise_on_no_answer=False,
            )
            if answer.rrset:
                addresses.extend(str(record) for record in answer)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException, OSError) as exc:
            errors.append(f"{record_type}: {type(exc).__name__}: {str(exc)[:140]}")

    normalized = sorted(
        {str(ipaddress.ip_address(value)) for value in addresses},
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    return normalized, errors


def _lookup_with_observation(
    query: str,
    kind: str,
    target: str,
    *,
    timeout: float,
    max_bytes: int,
    user_agent: str,
    pacer: _RequestPacer,
) -> Observation:
    try:
        result = _lookup_registration(
            query, kind, timeout=timeout, max_bytes=max_bytes, user_agent=user_agent, pacer=pacer
        )
        source = result["source"]
        fields = result["fields"]
        if kind == "domain":
            title = "Domain registration data"
            check_id = "WHOIS_DOMAIN_REGISTRATION"
            description = f"Registration metadata retrieved for {query} via {source}."
        else:
            title = "IP network registration data"
            check_id = "WHOIS_IP_REGISTRATION"
            description = f"Network allocation metadata retrieved for {query} via {source}."
        return Observation(
            check_id, title, "INFO", "OBSERVED", target, description,
            {
                "lookup_type": kind,
                "query": query,
                "source": source,
                "registry_server": result.get("registry_server"),
                "fields": fields,
                "fallback_reason": result.get("fallback_reason"),
            },
        )
    except WhoisLookupError as exc:
        return Observation(
            f"WHOIS_{kind.upper()}_LOOKUP_FAILED",
            f"{kind.upper()} registration lookup unavailable",
            "INFO", "ERROR", target,
            str(exc)[:500],
            {"lookup_type": kind, "query": query, "error": str(exc)[:500]},
        )


def _check_whois_sync(
    hostname: str,
    target: str,
    *,
    timeout: float,
    max_response_bytes: int,
    user_agent: str,
    requests_per_second: float,
) -> list[Observation]:
    safe_timeout = min(max(timeout, 2.0), 8.0)
    safe_cap = min(max(max_response_bytes, 16_384), WHOIS_RESPONSE_LIMIT)
    observations: list[Observation] = []
    pacer = _RequestPacer(requests_per_second)

    try:
        ip_literal = ipaddress.ip_address(hostname)
    except ValueError:
        ip_literal = None

    if ip_literal is None:
        observations.append(_lookup_with_observation(
            hostname, "domain", target,
            timeout=safe_timeout, max_bytes=safe_cap, user_agent=user_agent, pacer=pacer,
        ))

    try:
        addresses, dns_errors = _resolve_host_addresses(hostname, safe_timeout)
    except (OSError, ValueError, dns.exception.DNSException) as exc:
        addresses, dns_errors = [], [f"{type(exc).__name__}: {str(exc)[:180]}"]

    if addresses:
        observations.append(Observation(
            "WHOIS_SERVER_IP_ADDRESSES",
            "DNS A/AAAA addresses resolved",
            "INFO", "OBSERVED", target,
            f"Resolved {hostname} to {len(addresses)} address(es): {', '.join(addresses)}",
            {
                "hostname": hostname,
                "addresses": addresses,
                "address_count": len(addresses),
                "dns_errors": dns_errors,
                "resolution_note": (
                    "These are the IP addresses currently published by DNS. "
                    "A CDN, reverse proxy, or load balancer may expose edge addresses rather than the origin server."
                ),
            },
        ))
    else:
        observations.append(Observation(
            "WHOIS_SERVER_IP_RESOLUTION_FAILED",
            "No A/AAAA server address resolved",
            "INFO", "ERROR", target,
            f"No A or AAAA address could be resolved for {hostname}.",
            {"hostname": hostname, "dns_errors": dns_errors},
        ))

    public_addresses = [
        address for address in addresses
        if ipaddress.ip_address(address).is_global
    ]
    selected_addresses = public_addresses[:MAX_IP_LOOKUPS]
    for address in selected_addresses:
        observations.append(_lookup_with_observation(
            address, "ip", target,
            timeout=safe_timeout, max_bytes=safe_cap, user_agent=user_agent, pacer=pacer,
        ))

    omitted = max(0, len(public_addresses) - len(selected_addresses))
    if omitted:
        observations.append(Observation(
            "WHOIS_IP_LOOKUP_LIMIT",
            "IP registration lookup limit reached",
            "INFO", "OBSERVED", target,
            f"Skipped {omitted} additional public IP address(es); the per-domain limit is {MAX_IP_LOOKUPS}.",
            {"omitted_count": omitted, "limit": MAX_IP_LOOKUPS},
        ))

    non_global = [
        address for address in addresses
        if not ipaddress.ip_address(address).is_global
    ]
    if non_global:
        observations.append(Observation(
            "WHOIS_NON_GLOBAL_ADDRESSES",
            "Non-public DNS addresses not sent to registries",
            "INFO", "OBSERVED", target,
            f"Skipped registry lookups for non-global address(es): {', '.join(non_global)}",
            {"addresses": non_global},
        ))
    return observations


async def check_whois(
    hostname: str,
    target: str,
    *,
    timeout: float = 8.0,
    max_response_bytes: int = 1_048_576,
    user_agent: str = "STARI-CLI",
    requests_per_second: float = 1.0,
) -> list[Observation]:
    """Look up domain and resolved public-IP registration data.

    RDAP bootstrap is attempted first. Classic WHOIS referral lookup is the fallback.
    Resolved DNS addresses are reported separately from registration ownership;
    they may be CDN/reverse-proxy edge IPs rather than origin addresses.
    """
    normalized = hostname.strip().rstrip(".")
    if not normalized:
        return [Observation(
            "WHOIS_INVALID_HOSTNAME", "WHOIS hostname is empty", "INFO", "ERROR",
            target, "No hostname was available for registration lookup.", {},
        )]
    try:
        normalized = normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        return [Observation(
            "WHOIS_INVALID_HOSTNAME", "Invalid WHOIS hostname", "INFO", "ERROR",
            target, str(exc)[:250], {"hostname": hostname},
        )]
    return await asyncio.to_thread(
        _check_whois_sync,
        normalized,
        target,
        timeout=timeout,
        max_response_bytes=max_response_bytes,
        user_agent=user_agent,
        requests_per_second=requests_per_second,
    )
