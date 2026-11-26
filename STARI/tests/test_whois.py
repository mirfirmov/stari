import asyncio

import pytest

from stari.engines import whois


def test_extract_whois_referral_from_iana_and_referralserver():
    assert whois._extract_whois_referral("domain: example.com\nwhois: whois.registry.example\n") == "whois.registry.example"
    assert whois._extract_whois_referral("ReferralServer: whois://whois.ripe.net\n") == "whois.ripe.net"
    assert whois._extract_whois_referral("domain: example.com\n") is None


def test_parse_whois_fields_keeps_allowlist_and_omits_contact_data():
    raw = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar LLC
Creation Date: 1995-08-14T04:00:00Z
Name Server: NS1.EXAMPLE.COM
Registrant Name: Private Person
Registrant Email: private@example.com
"""
    fields = whois._parse_whois_fields(raw, "domain")
    assert fields["domain_name"] == ["EXAMPLE.COM"]
    assert fields["registrar"] == ["Example Registrar LLC"]
    assert fields["creation_date"] == ["1995-08-14T04:00:00Z"]
    assert "Registrant Name" not in str(fields)
    assert "private@example.com" not in str(fields)


def test_summarize_rdap_domain_extracts_registrar_status_and_events():
    data = {
        "ldhName": "EXAMPLE.COM",
        "handle": "D123",
        "status": ["active"],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
        }],
    }
    result = whois._summarize_rdap(data, "domain")
    assert result["domain_name"] == "EXAMPLE.COM"
    assert result["registrar"] == "Example Registrar"
    assert result["name_server"] == ["NS1.EXAMPLE.COM"]
    assert result["events"]["registration"] == "1995-08-14T04:00:00Z"


def test_summarize_rdap_ip_extracts_network_range_and_country():
    result = whois._summarize_rdap({
        "name": "GOOGLE",
        "handle": "NET-8-8-8-0-1",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "ipVersion": "v4",
        "country": "US",
        "type": "DIRECT ALLOCATION",
        "status": ["active"],
    }, "ip")
    assert result["network_name"] == "GOOGLE"
    assert result["start_address"] == "8.8.8.0"
    assert result["end_address"] == "8.8.8.255"
    assert result["country"] == "US"


def test_lookup_registration_uses_rdap_first(monkeypatch):
    calls = []

    def fake_rdap(kind, query, **kwargs):
        calls.append(("RDAP", kind, query))
        return {"domain_name": "EXAMPLE.COM", "registrar": "Example Registrar"}

    def unexpected_whois(*args, **kwargs):
        raise AssertionError("WHOIS should not be needed when RDAP succeeds")

    monkeypatch.setattr(whois, "_rdap_lookup", fake_rdap)
    monkeypatch.setattr(whois, "_whois_query", unexpected_whois)
    result = whois._lookup_registration(
        "example.com", "domain", timeout=3, max_bytes=100_000, user_agent="STARI"
    )
    assert calls == [("RDAP", "domain", "example.com")]
    assert result["source"] == "RDAP"
    assert result["fields"]["registrar"] == "Example Registrar"


def test_lookup_registration_falls_back_to_whois(monkeypatch):
    calls = []

    def fake_rdap(*args, **kwargs):
        raise OSError("RDAP unavailable")

    def fake_query(server, query, timeout, max_bytes, pacer=None):
        calls.append((server, query))
        if server == whois.WHOIS_IANA_SERVER:
            return "domain: example.com\nwhois: whois.registry.example\n"
        return "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n"

    monkeypatch.setattr(whois, "_rdap_lookup", fake_rdap)
    monkeypatch.setattr(whois, "_whois_query", fake_query)
    result = whois._lookup_registration(
        "example.com", "domain", timeout=3, max_bytes=100_000, user_agent="STARI"
    )
    assert calls == [
        ("whois.iana.org", "example.com"),
        ("whois.registry.example", "example.com"),
    ]
    assert result["source"] == "WHOIS"
    assert result["fields"]["registrar"] == ["Example Registrar"]
    assert "RDAP unavailable" in result["fallback_reason"]


def test_check_whois_resolves_addresses_and_looks_up_public_ip_only(monkeypatch):
    lookups = []
    monkeypatch.setattr(
        whois, "_resolve_host_addresses",
        lambda hostname, timeout: (["8.8.8.8", "192.168.1.10"], []),
    )

    def fake_lookup(query, kind, **kwargs):
        lookups.append((query, kind))
        return {
            "source": "RDAP",
            "registry_server": None,
            "fields": {"domain_name": "example.com"} if kind == "domain" else {"network_name": "PUBLIC-DNS"},
        }

    monkeypatch.setattr(whois, "_lookup_registration", fake_lookup)
    observations = whois._check_whois_sync(
        "example.com", "https://example.com", timeout=2,
        max_response_bytes=100_000, user_agent="STARI", requests_per_second=100,
    )
    assert lookups == [("example.com", "domain"), ("8.8.8.8", "ip")]
    address_observation = next(item for item in observations if item.check_id == "WHOIS_SERVER_IP_ADDRESSES")
    assert address_observation.evidence["addresses"] == ["8.8.8.8", "192.168.1.10"]
    assert any(item.check_id == "WHOIS_NON_GLOBAL_ADDRESSES" for item in observations)
    assert "origin server" in address_observation.evidence["resolution_note"]


def test_check_whois_runs_sync_lookup_in_a_thread(monkeypatch):
    expected = []

    def fake_sync(hostname, target, **kwargs):
        expected.append((hostname, target, kwargs["requests_per_second"]))
        return []

    monkeypatch.setattr(whois, "_check_whois_sync", fake_sync)
    result = asyncio.run(whois.check_whois(
        "Example.COM.", "https://example.com", requests_per_second=2.0
    ))
    assert result == []
    assert expected == [("example.com", "https://example.com", 2.0)]


def test_invalid_hostname_returns_error_observation():
    result = asyncio.run(whois.check_whois("", "https://example.com"))
    assert result[0].check_id == "WHOIS_INVALID_HOSTNAME"
    assert result[0].status == "ERROR"
