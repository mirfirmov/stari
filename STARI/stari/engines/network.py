from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver

from stari.core.models import Observation

DNS_RECORD_TYPES: tuple[str, ...] = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
    "HTTPS",
    "SVCB",
)


def _resolve_dns_record(hostname: str, record_type: str, timeout: float) -> dict[str, Any] | None:
    """Resolve one DNS RR type with the operating system's configured resolver."""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(max(timeout, 0.5), 3.0)
    answer = resolver.resolve(
        hostname,
        record_type,
        lifetime=min(max(timeout, 0.5), 3.0),
        search=False,
        raise_on_no_answer=False,
    )
    rrset = answer.rrset
    if rrset is None:
        return None

    values = [record.to_text() for record in rrset]
    return {
        "record_type": record_type,
        "records": values,
        "ttl_seconds": int(rrset.ttl),
        "query_name": answer.qname.to_text(),
        "canonical_name": answer.canonical_name.to_text(),
        "nameserver": answer.nameserver,
        "record_count": len(values),
    }


async def check_dns(
    hostname: str,
    target: str,
    *,
    requests_per_second: float = 1.0,
    query_timeout: float = 2.5,
) -> list[Observation]:
    """Collect common public DNS record sets and keep each RRset inspectable.

    Queries use the machine's configured recursive resolver. Missing RR types are
    normal and are omitted; timeout and resolver failures are reported distinctly.
    """
    hostname = hostname.strip().rstrip(".").encode("idna").decode("ascii").lower()
    if not hostname:
        return [Observation(
            "DNS_INVALID_HOSTNAME", "DNS hostname is empty", "INFO", "ERROR",
            target, "No hostname was available for DNS resolution.", {},
        )]

    observations: list[Observation] = []
    empty_types: list[str] = []
    interval = 1.0 / max(float(requests_per_second), 0.1)
    previous_query_at: float | None = None
    loop = asyncio.get_running_loop()

    for record_type in DNS_RECORD_TYPES:
        if previous_query_at is not None:
            elapsed = loop.time() - previous_query_at
            delay = interval - elapsed
            if delay > 0:
                await asyncio.sleep(delay)
        previous_query_at = loop.time()

        try:
            record_set = await asyncio.to_thread(
                _resolve_dns_record, hostname, record_type, query_timeout
            )
        except dns.resolver.NXDOMAIN as exc:
            return [Observation(
                "DNS_NXDOMAIN", "DNS name does not exist", "INFO", "ERROR",
                target,
                f"The configured DNS resolver returned NXDOMAIN for {hostname}.",
                {"hostname": hostname, "record_type": record_type, "error": str(exc)[:300]},
            )]
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            observations.append(Observation(
                f"DNS_{record_type}_QUERY_FAILED",
                f"DNS {record_type} query failed", "INFO", "ERROR", target,
                f"The resolver could not return the {record_type} record set: {exc}",
                {"hostname": hostname, "record_type": record_type,
                 "error_type": type(exc).__name__, "error": str(exc)[:300]},
            ))
            continue
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            observations.append(Observation(
                f"DNS_{record_type}_QUERY_FAILED",
                f"DNS {record_type} query failed", "INFO", "ERROR", target,
                f"Could not query {record_type}: {exc}",
                {"hostname": hostname, "record_type": record_type,
                 "error_type": type(exc).__name__, "error": str(exc)[:300]},
            ))
            continue

        if record_set is None:
            empty_types.append(record_type)
            continue

        values = record_set["records"]
        ttl = record_set["ttl_seconds"]
        value_text = " | ".join(values)
        observations.append(Observation(
            f"DNS_{record_type}_RECORDS",
            f"DNS {record_type} records",
            "INFO",
            "OBSERVED",
            target,
            f"{len(values)} record(s), TTL {ttl}s: {value_text}",
            record_set,
        ))

    if not any(item.check_id.startswith("DNS_") and item.status == "OBSERVED" for item in observations):
        if not observations:
            observations.append(Observation(
                "DNS_NO_RECORDS", "No supported DNS records returned", "INFO", "OBSERVED",
                target,
                f"DNS queries completed for {hostname}, but no records were returned for the queried types.",
                {"hostname": hostname, "queried_types": list(DNS_RECORD_TYPES),
                 "empty_types": empty_types},
            ))
    elif observations:

        first = next((item for item in observations if item.status == "OBSERVED"), None)
        if first is not None:
            first.evidence["no_records_for_types"] = empty_types

    return observations


def _name_to_text(parts: Any) -> str:
    return ", ".join(
        f"{key}={value}"
        for group in (parts or ())
        for key, value in group
    )


def _inspect_tls(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            certificate = tls_socket.getpeercert()
            certificate_der = tls_socket.getpeercert(binary_form=True)
            not_after = certificate.get("notAfter")
            not_before = certificate.get("notBefore")
            expires_at = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_after), tz=timezone.utc
            ) if not_after else None
            valid_from = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_before), tz=timezone.utc
            ) if not_before else None
            days_remaining = (
                (expires_at - datetime.now(timezone.utc)).days if expires_at else None
            )
            cipher_info = tls_socket.cipher()
            san_entries = [f"{kind}: {value}" for kind, value in certificate.get("subjectAltName", ())]
            subject = _name_to_text(certificate.get("subject", ()))
            issuer = _name_to_text(certificate.get("issuer", ()))
            return {
                "hostname_verified": True,
                "tls_version": tls_socket.version(),
                "cipher": cipher_info[0] if cipher_info else None,
                "cipher_protocol": cipher_info[1] if cipher_info else None,
                "cipher_bits": cipher_info[2] if cipher_info else None,
                "subject": subject,
                "issuer": issuer,
                "subject_alt_names": san_entries,
                "serial_number": certificate.get("serialNumber"),
                "certificate_version": certificate.get("version"),
                "valid_from": valid_from.isoformat() if valid_from else None,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "days_remaining": days_remaining,
                "sha256_fingerprint": hashlib.sha256(certificate_der).hexdigest().upper(),
            }


async def check_tls(
    hostname: str,
    target: str,
    port: int | None = None,
    *,
    timeout: float = 8.0,
) -> list[Observation]:
    if not target.startswith("https://"):
        return [Observation(
            "TLS_NOT_APPLICABLE", "TLS check skipped", "INFO", "SKIPPED",
            target, "The configured target uses HTTP rather than HTTPS.", {},
        )]
    try:
        details = await asyncio.to_thread(_inspect_tls, hostname, port or 443, timeout)
    except ssl.SSLCertVerificationError as exc:
        return [Observation(
            "TLS_CERTIFICATE_VERIFICATION_FAILED", "TLS certificate verification failed",
            "MEDIUM", "NEEDS_REVIEW", target,
            "The system TLS verifier rejected the certificate. Verify from another trusted client before treating this as a confirmed issue.",
            {"hostname": hostname, "port": port or 443,
             "error": str(exc)[:300], "error_type": type(exc).__name__},
        )]
    except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
        return [Observation(
            "TLS_CHECK_ERROR", "TLS inspection could not complete", "INFO", "ERROR",
            target, str(exc)[:300],
            {"hostname": hostname, "port": port or 443,
             "error_type": type(exc).__name__},
        )]

    days = details.get("days_remaining")
    severity = (
        "MEDIUM" if days is not None and days < 0
        else "LOW" if days is not None and days <= 21
        else "INFO"
    )
    status = "NEEDS_REVIEW" if severity != "INFO" else "OBSERVED"
    summary = (
        f"TLS {details.get('tls_version')} negotiated; "
        f"certificate expires in {days} day(s)." if days is not None
        else f"TLS {details.get('tls_version')} negotiated; certificate validity dates unavailable."
    )
    return [Observation(
        "TLS_CERTIFICATE_INSPECTED", "TLS certificate inspected", severity, status,
        target, summary, details,
    )]
