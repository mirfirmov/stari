from argparse import Namespace
from io import StringIO

from rich.console import Console

from stari import cli
from stari.core.config import make_config
from stari.core.models import Observation


def test_findings_and_report_parser_accept_scan_id_and_details():
    findings = cli.build_parser().parse_args(["findings", "--scan-id", "12", "--details"])
    assert findings.command == "findings"
    assert findings.scan_id == 12
    assert findings.details is True

    report = cli.build_parser().parse_args(["report", "--format", "json", "--scan-id", "12"])
    assert report.command == "report"
    assert report.format == "json"
    assert report.scan_id == 12


def test_run_scan_prints_database_observation_ids(monkeypatch, tmp_path):
    output = StringIO()
    fake_console = Console(file=output, force_terminal=False, color_system=None)
    monkeypatch.setattr(cli, "console", fake_console)
    import stari.ui as ui
    monkeypatch.setattr(ui, "console", fake_console)
    monkeypatch.setattr(cli, "project_dir", lambda: tmp_path / ".stari")
    monkeypatch.setattr(cli, "load_config", lambda: make_config("https://example.com"))

    async def fake_run_one(_command_name, *, extended=False, vuln=False):
        return [Observation(
            "DNS_A_RECORDS", "DNS A records", "INFO", "OBSERVED",
            "https://example.com", "1 record: 203.0.113.25",
            {"record_type": "A", "records": ["203.0.113.25"],
             "ttl_seconds": 300, "canonical_name": "example.com."},
        )]

    monkeypatch.setattr(cli, "_run_one", fake_run_one)
    cli._run_scan("dns")
    printed = output.getvalue()
    assert "203.0.113.25" in printed

    assert "1" in printed


def test_make_report_can_export_a_selected_historical_scan(monkeypatch, tmp_path):
    from stari.core.database import Database

    db = Database(tmp_path / ".stari" / "stari.sqlite3")
    scan_id = db.start_scan("https://example.com", "dns")
    db.save_observations(scan_id, [Observation(
        "DNS_A_RECORDS", "DNS A records", "INFO", "OBSERVED",
        "https://example.com", "1 record", {"records": ["203.0.113.25"]},
    )])
    db.finish_scan(scan_id)
    monkeypatch.setattr(cli, "get_database", lambda: db)
    output = tmp_path / "historical.json"
    cli._make_report(Namespace(scan_id=scan_id, format="json", output=str(output)))
    assert output.exists()
    assert "203.0.113.25" in output.read_text(encoding="utf-8")


def test_whois_command_is_registered_and_supported():
    parsed = cli.build_parser().parse_args(["whois"])
    assert parsed.command == "whois"


def test_run_one_calls_whois_engine_with_project_limits(monkeypatch):
    import asyncio

    config = make_config("https://example.com")
    config.requests_per_second = 2.0
    config.request_timeout_seconds = 9.0
    config.max_response_bytes = 250_000
    config.user_agent = "STARI-test"
    monkeypatch.setattr(cli, "load_config", lambda: config)
    called = {}

    async def fake_check_whois(hostname, target, **kwargs):
        called.update(hostname=hostname, target=target, **kwargs)
        return []

    monkeypatch.setattr(cli, "check_whois", fake_check_whois)
    result = asyncio.run(cli._run_one("whois"))
    assert result == []
    assert called == {
        "hostname": "example.com",
        "target": "https://example.com",
        "timeout": 9.0,
        "max_response_bytes": 250_000,
        "user_agent": "STARI-test",
        "requests_per_second": 2.0,
    }


def test_extended_commands_and_recon_flag_are_registered():
    parser = cli.build_parser()
    assert parser.parse_args(["admin"]).command == "admin"
    assert parser.parse_args(["emails"]).command == "emails"
    assert parser.parse_args(["ports"]).command == "ports"
    assert parser.parse_args(["cms"]).command == "cms"
    assert parser.parse_args(["subdomains"]).command == "subdomains"
    assert parser.parse_args(["xss"]).command == "xss"
    assert parser.parse_args(["sqli"]).command == "sqli"
    assert parser.parse_args(["vuln"]).command == "vuln"
    recon = parser.parse_args(["recon", "--extended", "--vuln"])
    assert recon.command == "recon" and recon.extended is True and recon.vuln is True


def test_run_one_forwards_passive_subdomain_limit_and_sources(monkeypatch):
    import asyncio

    config = make_config("https://example.com")
    monkeypatch.setattr(cli, "load_config", lambda: config)
    called = {}

    async def fake_check_subdomains(received_config, **kwargs):
        called["config"] = received_config
        called.update(kwargs)
        return []

    monkeypatch.setattr(cli, "check_subdomains", fake_check_subdomains)
    asyncio.run(cli._run_one(
        "subdomains", subdomain_limit=350, subdomain_sources=["crtsh", "otx"]
    ))
    assert called["config"] is config
    assert called["result_limit"] == 350
    assert called["selected_sources"] == ["crtsh", "otx"]


def test_new_free_commands_are_registered():
    parser = cli.build_parser()
    assert parser.parse_args(["crawl"]).command == "crawl"
    assert parser.parse_args(["crawl", "--max-pages", "40", "--max-scripts", "5"]).max_pages == 40
    assert parser.parse_args(["endpoints"]).command == "endpoints"
    assert parser.parse_args(["cors"]).command == "cors"
    assert parser.parse_args(["security"]).command == "security"
    diff = parser.parse_args(["diff", "--from", "1", "--to", "3"])
    assert diff.from_scan == 1 and diff.to_scan == 3
    project = parser.parse_args(["project", "add", "--target", "https://example.com", "--name", "example"])
    assert project.project_action == "add"
    switch = parser.parse_args(["project", "switch", "example"])
    assert switch.project_action == "switch" and switch.name == "example"


def test_run_one_forwards_crawler_limits(monkeypatch):
    import asyncio

    config = make_config("https://example.com")
    monkeypatch.setattr(cli, "load_config", lambda: config)
    called = {}

    async def fake_check_crawler(client, base_url, **kwargs):
        called.update(base_url=base_url, **kwargs)
        return []

    class FakeClient:
        def __init__(self, received_config):
            assert received_config is config
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None

    monkeypatch.setattr(cli, "SafeHTTPClient", FakeClient)
    monkeypatch.setattr(cli, "check_crawler", fake_check_crawler)
    result = asyncio.run(cli._run_one("crawl", crawl_max_pages=23, crawl_max_scripts=7))
    assert result == []
    assert called == {"base_url": "https://example.com", "max_pages": 23, "max_scripts": 7}


def test_admin_parser_exposes_deep_limits_and_custom_wordlist():
    parsed = cli.build_parser().parse_args([
        "admin", "--deep", "--max-paths", "500", "--crawl-pages", "32", "--wordlist", "routes.txt"
    ])
    assert parsed.deep is True
    assert parsed.max_paths == 500
    assert parsed.crawl_pages == 32
    assert parsed.wordlist == "routes.txt"


def test_admin_wordlist_loader_skips_comments_and_is_bounded(tmp_path):
    wordlist = tmp_path / "admin.txt"
    wordlist.write_text("# comment\n/admin/\nconsole # custom\n\n", encoding="utf-8")
    assert cli._load_admin_wordlist(str(wordlist)) == ("/admin/", "console")


def test_admin_dispatch_forwards_custom_wordlist_and_deep_options(monkeypatch, tmp_path):
    wordlist = tmp_path / "admin.txt"
    wordlist.write_text("/console\n/admin-area/\n", encoding="utf-8")
    captured = {}

    def fake_run_scan(command_name, **kwargs):
        captured["command"] = command_name
        captured.update(kwargs)

    monkeypatch.setattr(cli, "_run_scan", fake_run_scan)
    assert cli.dispatch([
        "admin", "--deep", "--max-paths", "500", "--crawl-pages", "30", "--wordlist", str(wordlist)
    ]) is True
    assert captured["command"] == "admin"
    assert captured["admin_deep"] is True
    assert captured["admin_custom_paths"] == ("/console", "/admin-area/")
    assert captured["admin_max_paths"] == 500
    assert captured["admin_crawl_pages"] == 30
