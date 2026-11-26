import asyncio

from stari.core.config import make_config
from stari.engines.subdomains import (
    SOURCE_NAMES,
    _parse_certspotter,
    _parse_crtsh,
    _parse_hackertarget,
    _parse_otx,
    _parse_urlscan,
    _parse_wayback,
    check_subdomains,
)


def test_passive_search_merges_sources_and_never_resolves_or_probes_target():
    config = make_config("https://example.com")
    config.requests_per_second = 10_000.0
    observed_calls = []

    async def fake_crtsh(_client, domain, _max_bytes):
        observed_calls.append(("crtsh", domain))
        return {"www.example.com", "blog.example.com", "notexample.com"}, None

    async def fake_wayback(_client, domain, _max_bytes):
        observed_calls.append(("wayback", domain))
        return {"blog.example.com", "old.example.com"}, None

    rows = asyncio.run(check_subdomains(
        config,
        selected_sources=["crtsh", "wayback"],
        fetchers={"crtsh": fake_crtsh, "wayback": fake_wayback},
    ))

    assert rows[0].status == "FOUND"
    evidence = rows[0].evidence
    found = {item["hostname"]: set(item["sources"]) for item in evidence["subdomains"]}
    assert found == {
        "blog.example.com": {"crtsh", "wayback"},
        "old.example.com": {"wayback"},
        "www.example.com": {"crtsh"},
    }
    assert "notexample.com" not in found
    assert evidence["dns_queries_to_candidates"] == 0
    assert evidence["target_http_requests"] == 0
    assert evidence["target_tcp_connections"] == 0
    assert evidence["wordlist_bruteforce"] is False
    assert observed_calls == [("crtsh", "example.com"), ("wayback", "example.com")]


def test_cert_transparency_parsers_filter_outside_names_and_normalize_wildcards():
    crt_payload = [
        {"name_value": "example.com\n*.blog.example.com\napi.example.com"},
        {"common_name": "outside.example.net"},
    ]
    certspotter_payload = [
        {"dns_names": ["example.com", "*.shop.example.com", "notexample.com"]}
    ]
    assert _parse_crtsh(crt_payload, "example.com") == {
        "blog.example.com", "api.example.com"
    }
    assert _parse_certspotter(certspotter_payload, "example.com") == {
        "shop.example.com"
    }


def test_hackertarget_parser_uses_hostname_column_and_filters_suffix_tricks():
    payload = "blog.example.com,203.0.113.3\napi.example.com,203.0.113.4\nnotexample.com,203.0.113.5\n"
    assert _parse_hackertarget(payload, "example.com") == {
        "blog.example.com", "api.example.com"
    }


def test_otx_parser_extracts_passive_dns_hostnames():
    payload = {
        "passive_dns": [
            {"hostname": "mail.example.com"},
            {"hostname": "example.com"},
            {"hostname": "evil-example.com"},
        ]
    }
    assert _parse_otx(payload, "example.com") == {"mail.example.com"}


def test_urlscan_parser_extracts_domains_and_urls_from_public_scan_metadata():
    payload = {
        "results": [
            {"page": {"domain": "blog.example.com", "url": "https://blog.example.com/post"}},
            {"task": {"domain": "cdn.example.net", "url": "https://api.example.com/v1"}},
            {"page": {"domain": "example.com"}},
        ]
    }
    assert _parse_urlscan(payload, "example.com") == {
        "blog.example.com", "api.example.com"
    }


def test_wayback_parser_extracts_hosts_from_archived_urls():
    payload = [
        ["original"],
        ["https://old.example.com/story"],
        ["http://www.example.com/"],
        ["https://notexample.com/"],
    ]
    assert _parse_wayback(payload, "example.com") == {
        "old.example.com", "www.example.com"
    }


def test_provider_failure_does_not_abort_other_passive_sources():
    config = make_config("https://example.com")
    config.requests_per_second = 10_000.0

    async def failing(_client, _domain, _max_bytes):
        return set(), "HTTP 429"

    async def successful(_client, domain, _max_bytes):
        return {f"blog.{domain}"}, None

    rows = asyncio.run(check_subdomains(
        config,
        selected_sources=["crtsh", "otx"],
        fetchers={"crtsh": failing, "otx": successful},
    ))
    evidence = rows[0].evidence
    assert rows[0].status == "FOUND"
    assert evidence["source_results"]["crtsh"]["status"] == "ERROR"
    assert evidence["source_results"]["otx"]["status"] == "FOUND"
    assert evidence["failed_source_count"] == 1


def test_all_provider_failures_are_reported_as_source_errors():
    config = make_config("https://example.com")

    async def failing(_client, _domain, _max_bytes):
        return set(), "HTTP 503"

    rows = asyncio.run(check_subdomains(
        config, selected_sources=["crtsh"], fetchers={"crtsh": failing}
    ))
    assert rows[0].status == "SOURCE_ERRORS"
    assert rows[0].evidence["target_http_requests"] == 0


def test_ip_target_is_rejected_before_provider_calls():
    config = make_config("https://192.0.2.10")

    async def fail_if_called(_client, _domain, _max_bytes):
        raise AssertionError("No public index lookup should run for an IP target")

    rows = asyncio.run(check_subdomains(
        config, selected_sources=["crtsh"], fetchers={"crtsh": fail_if_called}
    ))
    assert rows[0].status == "ERROR"
    assert rows[0].evidence["reason"] == "target_is_ip_address"


def test_unknown_provider_is_reported_and_valid_provider_still_runs():
    config = make_config("https://example.com")

    async def fake(_client, domain, _max_bytes):
        return {f"blog.{domain}"}, None

    rows = asyncio.run(check_subdomains(
        config, selected_sources=["unknown", "crtsh"], fetchers={"crtsh": fake}
    ))
    assert rows[0].status == "FOUND"
    assert rows[0].evidence["invalid_sources"] == ["unknown"]


def test_default_source_registry_is_passive_public_index_set():
    assert SOURCE_NAMES == (
        "crtsh", "certspotter", "hackertarget", "otx", "urlscan", "wayback"
    )


def test_subdomains_parser_accepts_result_limit_and_repeated_sources():
    from stari.cli import build_parser

    parsed = build_parser().parse_args([
        "subdomains", "--limit", "1000", "--source", "crtsh", "--source", "otx"
    ])
    assert parsed.command == "subdomains"
    assert parsed.limit == 1000
    assert parsed.source == ["crtsh", "otx"]
