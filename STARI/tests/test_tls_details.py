import asyncio

from stari.core.models import Observation
from stari.engines import network


def test_tls_not_applicable_for_http_target():
    observations = asyncio.run(network.check_tls("example.com", "http://example.com", 80))
    assert observations[0].check_id == "TLS_NOT_APPLICABLE"
    assert observations[0].status == "SKIPPED"


def test_tls_observation_keeps_certificate_metadata(monkeypatch):
    details = {
        "hostname_verified": True,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "cipher_bits": 128,
        "subject": "commonName=example.com",
        "issuer": "commonName=Example CA",
        "subject_alt_names": ["DNS:example.com", "DNS:www.example.com"],
        "serial_number": "1234",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "expires_at": "2027-01-01T00:00:00+00:00",
        "days_remaining": 44,
        "sha256_fingerprint": "AB" * 32,
    }
    monkeypatch.setattr(network, "_inspect_tls", lambda *args: details)
    observations = asyncio.run(network.check_tls("example.com", "https://example.com", 443))
    assert observations[0].evidence["tls_version"] == "TLSv1.3"
    assert observations[0].evidence["subject_alt_names"] == details["subject_alt_names"]
    assert observations[0].evidence["sha256_fingerprint"] == "AB" * 32
