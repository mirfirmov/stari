import asyncio

import dns.resolver

from stari.core.models import Observation
from stari.engines import network


def test_dns_collects_multiple_record_sets(monkeypatch):
    def fake_lookup(hostname, record_type, timeout):
        records = {
            "A": {
                "record_type": "A", "records": ["192.0.2.10", "192.0.2.11"],
                "ttl_seconds": 300, "query_name": "example.com.",
                "canonical_name": "example.com.", "nameserver": "192.0.2.53",
                "record_count": 2,
            },
            "MX": {
                "record_type": "MX", "records": ["10 mail.example.com."],
                "ttl_seconds": 600, "query_name": "example.com.",
                "canonical_name": "example.com.", "nameserver": "192.0.2.53",
                "record_count": 1,
            },
        }
        return records.get(record_type)

    monkeypatch.setattr(network, "_resolve_dns_record", fake_lookup)
    observations = asyncio.run(network.check_dns(
        "example.com", "https://example.com", requests_per_second=1000
    ))

    by_type = {item.evidence.get("record_type"): item for item in observations}
    assert by_type["A"].evidence["records"] == ["192.0.2.10", "192.0.2.11"]
    assert by_type["A"].evidence["ttl_seconds"] == 300
    assert by_type["MX"].evidence["records"] == ["10 mail.example.com."]
    assert len(observations) == 2


def test_dns_reports_nxdomain_distinctly(monkeypatch):
    def fake_lookup(hostname, record_type, timeout):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(network, "_resolve_dns_record", fake_lookup)
    observations = asyncio.run(network.check_dns(
        "missing.example", "https://missing.example", requests_per_second=1000
    ))
    assert len(observations) == 1
    assert observations[0].check_id == "DNS_NXDOMAIN"
    assert observations[0].status == "ERROR"


def test_dns_reports_empty_result_without_calling_it_an_error(monkeypatch):
    monkeypatch.setattr(network, "_resolve_dns_record", lambda *args: None)
    observations = asyncio.run(network.check_dns(
        "empty.example", "https://empty.example", requests_per_second=1000
    ))
    assert len(observations) == 1
    assert observations[0].check_id == "DNS_NO_RECORDS"
    assert observations[0].status == "OBSERVED"


def test_dns_resolver_uses_no_search_and_records_ttl(monkeypatch):
    class FakeRecord:
        def to_text(self):
            return "203.0.113.25"

    class FakeRRset:
        ttl = 180

        def __iter__(self):
            return iter([FakeRecord()])

    class FakeName:
        def to_text(self):
            return "example.com."

    class FakeAnswer:
        rrset = FakeRRset()
        qname = FakeName()
        canonical_name = FakeName()
        nameserver = "192.0.2.53"

    class FakeResolver:
        def __init__(self, configure=True):
            assert configure is True
            self.timeout = None
            self.kwargs = None

        def resolve(self, hostname, record_type, **kwargs):
            self.kwargs = kwargs
            assert hostname == "example.com"
            assert record_type == "A"
            return FakeAnswer()

    resolver = FakeResolver()
    monkeypatch.setattr(network.dns.resolver, "Resolver", lambda configure=True: resolver)
    result = network._resolve_dns_record("example.com", "A", 2.0)

    assert result["records"] == ["203.0.113.25"]
    assert result["ttl_seconds"] == 180
    assert result["nameserver"] == "192.0.2.53"
    assert resolver.kwargs["search"] is False
    assert resolver.kwargs["raise_on_no_answer"] is False
