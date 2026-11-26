from __future__ import annotations

import argparse
import asyncio
import cmd
import shlex
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from stari import __version__
from stari.core.config import (
    add_project, list_projects, load_config, make_config, project_dir, save_config, switch_project,
)
from stari.core.database import Database
from stari.core.models import Observation
from stari.engines.headers import check_headers
from stari.engines.crawler import check_crawler
from stari.engines.security import check_cors
from stari.analysis.diff import compare_observations
from stari.engines.admin_finder import check_admin_panels
from stari.engines.cms import check_cms
from stari.engines.emails import check_emails
from stari.engines.ports import check_ports
from stari.engines.subdomains import check_subdomains
from stari.engines.parameter_audit import check_sqli_boolean_and_error, check_xss_reflection
from stari.engines.http_client import SafeHTTPClient
from stari.engines.network import check_dns, check_tls
from stari.engines.whois import check_whois
from stari.engines.recon import ReconEngine
from stari.engines.robots import check_robots
from stari.engines.sitemap import check_sitemap
from stari.i18n import choose_language, current_language, load_saved_language, tr
from stari.reporting import export_report
from stari.ui import (
    banner,
    console,
    key_value_panel,
    observations_table,
    render_observation_detail,
    render_scan_details,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stari",
        description=tr("app_description"),
    )
    parser.add_argument("--version", action="version", version=f"stari {__version__}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help=tr("help_init"), description=tr("help_init"))
    init.add_argument("--target", required=True, help=tr("target_arg"))
    init.add_argument("--name", help=tr("name_arg"))
    init.add_argument("--force", action="store_true", help=tr("force_arg"))

    sub.add_parser("scope", help=tr("help_scope"))
    sub.add_parser("robots", help=tr("help_robots"))
    sub.add_parser("sitemap", help=tr("help_sitemap"))
    sub.add_parser("headers", help=tr("help_headers"))
    sub.add_parser("dns", help=tr("help_dns"))
    sub.add_parser("whois", help=tr("help_whois"))
    sub.add_parser("tls", help=tr("help_tls"))
    admin = sub.add_parser("admin", help=tr("help_admin"))
    admin.add_argument("--deep", action="store_true", help=tr("admin_deep_help"))
    admin.add_argument("--max-paths", type=int, help=tr("admin_max_paths_help"))
    admin.add_argument("--crawl-pages", type=int, default=24, help=tr("admin_crawl_pages_help"))
    admin.add_argument("--wordlist", help=tr("admin_wordlist_help"))
    sub.add_parser("emails", help=tr("help_emails"))
    sub.add_parser("ports", help=tr("help_ports"))
    sub.add_parser("cms", help=tr("help_cms"))
    subdomains = sub.add_parser("subdomains", help=tr("help_subdomains"))
    subdomains.add_argument(
        "--limit", type=int, default=500,
        help=tr("subdomains_limit_help"),
    )
    subdomains.add_argument(
        "--source", action="append",
        choices=["crtsh", "certspotter", "hackertarget", "otx", "urlscan", "wayback"],
        help=tr("subdomains_source_help"),
    )
    sub.add_parser("xss", help=tr("help_xss"))
    sub.add_parser("sqli", help=tr("help_sqli"))
    sub.add_parser("vuln", help=tr("help_vuln"))
    recon = sub.add_parser("recon", help=tr("help_recon"))
    recon.add_argument("--extended", action="store_true", help=tr("help_recon_extended"))
    recon.add_argument("--vuln", action="store_true", help=tr("help_recon_vuln"))

    findings = sub.add_parser("findings", help=tr("help_findings"))
    findings.add_argument("--scan-id", type=int, help=tr("scan_id_arg"))
    findings.add_argument("--details", action="store_true", help=tr("show_evidence_arg"))

    inspect = sub.add_parser("inspect", help=tr("help_inspect"))
    inspect.add_argument("id", type=int, help="observation database id")
    sub.add_parser("history", help=tr("help_history"))

    report = sub.add_parser("report", help=tr("help_report"))
    report.add_argument("--format", choices=["md", "json"], default="md", help=tr("format_arg"))
    report.add_argument("--output", help=tr("output_arg"))
    report.add_argument("--scan-id", type=int, help=tr("scan_id_arg"))

    crawl = sub.add_parser("crawl", help=tr("help_crawl"))
    crawl.add_argument("--max-pages", type=int, default=100, help=tr("crawl_pages_help"))
    crawl.add_argument("--max-scripts", type=int, default=30, help=tr("crawl_scripts_help"))
    endpoints = sub.add_parser("endpoints", help=tr("help_endpoints"))
    endpoints.add_argument("--max-pages", type=int, default=100, help=tr("crawl_pages_help"))
    endpoints.add_argument("--max-scripts", type=int, default=30, help=tr("crawl_scripts_help"))
    sub.add_parser("cors", help=tr("help_cors"))
    sub.add_parser("security", help=tr("help_security"))

    diff = sub.add_parser("diff", help=tr("help_diff"))
    diff.add_argument("--from", dest="from_scan", type=int, required=True, help=tr("diff_from_help"))
    diff.add_argument("--to", dest="to_scan", type=int, help=tr("diff_to_help"))

    project = sub.add_parser("project", help=tr("help_project"))
    project_actions = project.add_subparsers(dest="project_action", required=True)
    project_add = project_actions.add_parser("add", help=tr("help_project_add"))
    project_add.add_argument("--target", required=True, help=tr("target_arg"))
    project_add.add_argument("--name", help=tr("name_arg"))
    project_switch = project_actions.add_parser("switch", help=tr("help_project_switch"))
    project_switch.add_argument("name", help=tr("project_identifier_help"))
    project_actions.add_parser("list", help=tr("help_project_list"))
    project_actions.add_parser("current", help=tr("help_project_current"))
    sub.add_parser("projects", help=tr("help_project_list"))

    sub.add_parser("help", help=tr("help_commands"))
    sub.add_parser("exit", help=tr("help_exit"))
    sub.add_parser("quit", help=tr("help_exit"))
    return parser


def _load_admin_wordlist(path_value: str | None) -> tuple[str, ...]:
    """Load at most 1,000 custom admin paths from a UTF-8 text file."""
    if not path_value:
        return ()
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"admin wordlist not found: {path}")
    entries: list[str] = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            entries.append(value)
            if len(entries) >= 1000:
                break
    return tuple(entries)


def get_database() -> Database:
    return Database(project_dir() / "stari.sqlite3")


def _print_help() -> None:
    if current_language() == "ru":
        rows = [
            ("init --target DOMAIN", "Создать проект и задать разрешённую цель"),
            ("scope", "Показать настройки проекта и область проверки"),
            ("recon", "Запустить все базовые проверки и показать доказательства"),
            ("robots", "Получить robots.txt и разобрать директивы"),
            ("sitemap", "Получить sitemap.xml и показать URL в scope"),
            ("headers", "Показать HTTP-заголовки и проверить защитные заголовки"),
            ("dns", "Получить A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS и SVCB"),
            ("whois", "Получить регистрационные данные домена и DNS IP через WHOIS/RDAP"),
            ("tls", "Показать TLS, сертификат, SAN и SHA-256 fingerprint"),
            ("admin [--deep] [--max-paths N] [--crawl-pages N] [--wordlist FILE]", "Искать реальные страницы входа и админ-интерфейсы; отдельно показывать restricted и uncertain"),
            ("emails", "Собрать публично опубликованные адреса из страниц в scope"),
            ("ports", "Проверить ограниченный набор распространённых веб TCP-портов"),
            ("cms", "Определить CMS и веб-платформу по публичным сигнатурам"),
            ("subdomains [--limit N] [--source NAME]", "Пассивный поиск поддоменов по публичным OSINT-источникам; без DNS-проверки"),
            ("xss", "Проверить отражение безвредного HTML-маркера в GET-параметрах"),
            ("sqli", "Проверить GET-параметры на SQL-ошибки и boolean-differential"),
            ("vuln", "Запустить эвристические проверки XSS и SQLi"),
            ("recon --extended", "Запустить базовые проверки и дополнительные модули"),
            ("recon --vuln", "Добавить ограниченные проверки XSS и SQLi"),
            ("findings [--scan-id ID] [--details]", "Показать результаты выбранной проверки"),
            ("inspect ID", "Открыть результат и полные доказательства из истории"),
            ("history", "Показать историю всех проверок"),
            ("report --format md|json [--scan-id ID]", "Экспортировать отчёт выбранной проверки"),
            ("crawl [--max-pages N]", "Обойти страницы в scope, найти формы, JS и API-endpoint'ы"),
            ("endpoints", "Показать маршруты и API-endpoint'ы из ограниченного обхода"),
            ("cors", "Проверить CORS с синтетическим Origin без credentials"),
            ("security", "Запустить аудит заголовков, cookies и CORS"),
            ("diff --from ID [--to ID]", "Сравнить результаты двух проверок"),
            ("project add|switch|list|current", "Управлять отдельными проектами и их историей"),
            ("help", "Показать список команд"),
            ("exit", "Закрыть консоль"),
        ]
    else:
        rows = [
            ("init --target DOMAIN", "Create a project and define its allowed target"),
            ("scope", "Show project settings and target scope"),
            ("recon", "Run baseline checks and display collected evidence"),
            ("robots", "Fetch robots.txt and parse its directives"),
            ("sitemap", "Fetch sitemap.xml and display in-scope URLs"),
            ("headers", "Display HTTP headers and review security headers"),
            ("dns", "Query A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS and SVCB"),
            ("whois", "Look up domain and DNS IP registration through WHOIS/RDAP"),
            ("tls", "Display TLS, certificate, SANs and SHA-256 fingerprint"),
            ("admin [--deep] [--max-paths N] [--crawl-pages N] [--wordlist FILE]", "Find real login pages and admin interfaces; separate restricted and uncertain routes"),
            ("emails", "Collect publicly published email addresses from in-scope pages"),
            ("ports", "Check a limited set of common web TCP ports"),
            ("cms", "Fingerprint CMS and web platforms using public signatures"),
            ("subdomains [--limit N] [--source NAME]", "Passive subdomain discovery from public OSINT indexes; no DNS checks"),
            ("xss", "Check GET parameters for reflection of a harmless HTML canary"),
            ("sqli", "Check GET parameters for SQL errors and boolean differentials"),
            ("vuln", "Run heuristic XSS and SQLi checks"),
            ("recon --extended", "Run baseline checks and the additional modules"),
            ("recon --vuln", "Include bounded XSS and SQLi checks"),
            ("findings [--scan-id ID] [--details]", "Show results from a selected scan"),
            ("inspect ID", "Open a finding and its evidence from scan history"),
            ("history", "Show all recorded scans"),
            ("report --format md|json [--scan-id ID]", "Export a selected scan report"),
            ("crawl [--max-pages N]", "Crawl in-scope pages and inventory forms, JS and API endpoints"),
            ("endpoints", "Show routes and API endpoints from a bounded crawl"),
            ("cors", "Review CORS using a synthetic Origin without credentials"),
            ("security", "Audit response headers, cookies and CORS"),
            ("diff --from ID [--to ID]", "Compare two saved scans"),
            ("project add|switch|list|current", "Manage separate projects and their scan history"),
            ("help", "Show available commands"),
            ("exit", "Close the console"),
        ]
    table = Table(title=tr("commands_title"), header_style="bold bright_magenta", expand=True)
    table.add_column(tr("command"), style="cyan", no_wrap=True)
    table.add_column(tr("description"))
    for command_name, description in rows:
        table.add_row(command_name.lower(), description.lower())
    console.print(table)
    console.print(f"[dim]{tr('language_change_help')}[/]")


def _store_scan(mode: str, observations: list[Observation]) -> int:
    config = load_config()
    db = get_database()
    scan_id = db.start_scan(config.base_url, mode)
    try:
        db.save_observations(scan_id, observations)
    finally:
        db.finish_scan(scan_id)
    return scan_id


async def _run_one(
    command_name: str,
    *,
    extended: bool = False,
    vuln: bool = False,
    subdomain_limit: int = 500,
    subdomain_sources: list[str] | None = None,
    crawl_max_pages: int = 100,
    crawl_max_scripts: int = 30,
    admin_deep: bool = False,
    admin_custom_paths: tuple[str, ...] = (),
    admin_crawl_pages: int = 18,
    admin_max_paths: int | None = None,
) -> list[Observation]:
    config = load_config()
    parsed_target = urlsplit(config.base_url)
    host = parsed_target.hostname or config.allowed_hosts[0]
    port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
    if command_name == "recon":
        return await ReconEngine(config).run(include_extended=extended, include_vuln=vuln)
    if command_name == "subdomains":
        return await check_subdomains(
            config,
            result_limit=subdomain_limit,
            selected_sources=subdomain_sources,
        )
    if command_name == "dns":
        return await check_dns(
            host, config.base_url,
            requests_per_second=config.requests_per_second,
        )
    if command_name == "whois":
        return await check_whois(
            host, config.base_url,
            timeout=config.request_timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            user_agent=config.user_agent,
            requests_per_second=config.requests_per_second,
        )
    if command_name == "tls":
        return await check_tls(
            host, config.base_url, port,
            timeout=config.request_timeout_seconds,
        )
    if command_name == "ports":
        return await check_ports(
            host, config.base_url,
            timeout=min(config.request_timeout_seconds, 3.0),
            requests_per_second=config.requests_per_second,
            allowed_hosts=config.allowed_hosts,
        )
    async with SafeHTTPClient(config) as client:
        if command_name in {"crawl", "endpoints"}:
            return await check_crawler(
                client, config.base_url,
                max_pages=crawl_max_pages, max_scripts=crawl_max_scripts,
            )
        if command_name == "cors":
            return await check_cors(client, config.base_url)
        if command_name == "security":
            header_rows, cors_rows = await asyncio.gather(
                check_headers(client, config.base_url),
                check_cors(client, config.base_url),
            )
            return [*header_rows, *cors_rows]
        if command_name == "xss":
            return await check_xss_reflection(client, config.base_url)
        if command_name == "sqli":
            return await check_sqli_boolean_and_error(client, config.base_url)
        if command_name == "vuln":
            xss_rows, sqli_rows = await asyncio.gather(
                check_xss_reflection(client, config.base_url),
                check_sqli_boolean_and_error(client, config.base_url),
            )
            return [*xss_rows, *sqli_rows]
        if command_name == "robots":
            return await check_robots(client, config.base_url)
        if command_name == "sitemap":
            return await check_sitemap(client, config.base_url)
        if command_name == "headers":
            return await check_headers(client, config.base_url)
        if command_name == "admin":
            return await check_admin_panels(
                client,
                config.base_url,
                deep=admin_deep,
                custom_paths=admin_custom_paths,
                crawl_pages=admin_crawl_pages,
                max_paths=admin_max_paths,
            )
        if command_name == "emails":
            return await check_emails(client, config.base_url)
        if command_name == "cms":
            return await check_cms(client, config.base_url)
    raise ValueError(f"unsupported scan command: {command_name}")


def _run_scan(
    command_name: str,
    *,
    extended: bool = False,
    vuln: bool = False,
    subdomain_limit: int = 500,
    subdomain_sources: list[str] | None = None,
    crawl_max_pages: int = 100,
    crawl_max_scripts: int = 30,
    admin_deep: bool = False,
    admin_custom_paths: tuple[str, ...] = (),
    admin_crawl_pages: int = 18,
    admin_max_paths: int | None = None,
) -> None:
    config = load_config()
    console.print(Text(f"{tr('target')}: {config.base_url}", style="bold"))
    console.print(f"[dim]{tr('scope_limited')}[/]\n")
    run_kwargs = {"extended": extended, "vuln": vuln}
    if command_name == "subdomains":
        run_kwargs.update({"subdomain_limit": subdomain_limit, "subdomain_sources": subdomain_sources})
    if command_name in {"crawl", "endpoints"}:
        run_kwargs.update({"crawl_max_pages": crawl_max_pages, "crawl_max_scripts": crawl_max_scripts})
    if command_name == "admin":
        run_kwargs.update({
            "admin_deep": admin_deep,
            "admin_custom_paths": admin_custom_paths,
            "admin_crawl_pages": admin_crawl_pages,
            "admin_max_paths": admin_max_paths,
        })
    observations = asyncio.run(_run_one(command_name, **run_kwargs))
    if command_name == "recon":
        scan_mode = "recon" + ("-extended" if extended else "") + ("-vuln" if vuln else "")
    else:
        scan_mode = command_name
    scan_id = _store_scan(scan_mode, observations)

    saved_observations = get_database().list_observations(scan_id)
    observations_table(saved_observations, title=f"{scan_mode.upper()} — {tr('scan')} #{scan_id}")
    render_scan_details(scan_mode, saved_observations)
    console.print(f"\n[green]{tr('completed', count=len(observations))}[/]")


def _show_scope() -> None:
    config = load_config()
    key_value_panel(tr("project_scope"), {
        tr("project"): config.project_name,
        tr("base_url"): config.base_url,
        tr("allowed_hosts"): ", ".join(config.allowed_hosts),
        tr("user_agent"): config.user_agent,
        tr("request_rate"): tr("request_rate_value", value=f"{config.requests_per_second:g}"),
        tr("response_cap"): tr("response_cap_value", value=f"{config.max_response_bytes:,}"),
        tr("timeout"): tr("timeout_value", value=f"{config.request_timeout_seconds:g}"),
    })


def _show_findings(scan_id: int | None = None, *, show_details: bool = False) -> None:
    db = get_database()
    scan = db.get_scan(scan_id) if scan_id is not None else db.latest_scan()
    if not scan:
        console.print(f"[yellow]{tr('no_scans')}[/]")
        return
    observations = db.list_observations(int(scan["id"]))
    observations_table(observations, title=f"{tr('scan').capitalize()} #{scan['id']} — {scan['mode']}")
    if show_details:
        for row in observations:
            render_observation_detail({**row, "scan_id": scan["id"], "scan_mode": scan["mode"]})


def _inspect_observation(observation_id: int) -> None:
    item = get_database().get_observation(observation_id)
    if item is None:
        console.print(Text(tr("observation_missing_any", id=observation_id), style="yellow"))
        return
    render_observation_detail(item)


def _show_history() -> None:
    rows = get_database().list_scans()
    if not rows:
        console.print(Text(tr("no_scan_history"), style="yellow"))
        return
    table = Table(title=tr("scan_history"), header_style="bold bright_magenta", expand=True)
    for column in (tr("scan_id"), tr("mode").capitalize(), tr("target"), tr("started"), tr("observations")):
        table.add_column(column)
    for row in rows:
        table.add_row(str(row["id"]), Text(str(row["mode"])), Text(str(row["target"])),
                      Text(str(row["started_at"])), str(row["observation_count"]))
    console.print(table)


def _show_projects() -> None:
    rows = list_projects()
    if not rows:
        console.print(Text(tr("no_projects"), style="yellow"))
        return
    table = Table(title=tr("projects_title"), header_style="bold bright_magenta", expand=True)
    table.add_column("slug", style="cyan", no_wrap=True)
    table.add_column(tr("project"))
    table.add_column(tr("target"), overflow="fold")
    table.add_column(tr("status"), no_wrap=True)
    for item in rows:
        active_label = tr("project_active") if item["active"] else ""
        table.add_row(Text(str(item["slug"])), Text(str(item["project_name"])),
                      Text(str(item["base_url"])), active_label)
    console.print(table)


def _show_diff(from_scan_id: int, to_scan_id: int | None = None) -> None:
    db = get_database()
    before_scan = db.get_scan(from_scan_id)
    after_scan = db.get_scan(to_scan_id) if to_scan_id is not None else db.latest_scan()
    if before_scan is None:
        console.print(Text(tr("diff_scan_missing", id=from_scan_id), style="yellow"))
        return
    if after_scan is None:
        console.print(Text(tr("diff_no_target"), style="yellow"))
        return
    if int(before_scan["id"]) == int(after_scan["id"]):
        console.print(Text(tr("diff_same_scan"), style="yellow"))
        return
    if before_scan["target"] != after_scan["target"]:
        console.print(Text(tr("diff_target_mismatch", before=before_scan["target"], after=after_scan["target"]), style="yellow"))
        return
    before_rows = db.list_observations(int(before_scan["id"]))
    after_rows = db.list_observations(int(after_scan["id"]))
    result = compare_observations(before_rows, after_rows)
    table = Table(title=tr("diff_title", before=before_scan["id"], after=after_scan["id"]), header_style="bold bright_magenta", expand=True)
    table.add_column(tr("diff_state"), no_wrap=True)
    table.add_column("check id", style="cyan")
    table.add_column(tr("target"), overflow="fold")
    table.add_column(tr("diff_before"), overflow="fold")
    table.add_column(tr("diff_after"), overflow="fold")
    labels = {
        "new": tr("diff_new"), "resolved": tr("diff_resolved"),
        "changed": tr("diff_changed"), "unchanged": tr("diff_unchanged"),
    }
    colors = {"new": "green", "resolved": "blue", "changed": "yellow", "unchanged": "dim"}
    for state in ("new", "resolved", "changed", "unchanged"):
        for item in result[state]:
            old = item.get("before") or {}
            new = item.get("after") or {}
            row = new or old
            table.add_row(
                f"[{colors[state]}]{labels[state]}[/]",
                Text(str(row.get("check_id", ""))), Text(str(row.get("target", ""))),
                str(old.get("status", "—")), str(new.get("status", "—")),
            )
    console.print(table)
    summary = " | ".join(f"{labels[key]}: {len(result[key])}" for key in ("new", "resolved", "changed", "unchanged"))
    console.print(f"[dim]{summary}[/]")


def _handle_project_command(args: argparse.Namespace) -> None:
    action = getattr(args, "project_action", None)
    if action == "list":
        _show_projects()
        return
    if action == "current":
        _show_scope()
        return
    if action == "add":
        config = make_config(args.target, args.name)
        slug = add_project(config)
        Database(project_dir() / "stari.sqlite3")
        console.print(Text(tr("project_added", name=config.project_name, slug=slug), style="green"))
        _show_scope()
        return
    if action == "switch":
        selected = switch_project(args.name)
        Database(project_dir() / "stari.sqlite3")
        console.print(Text(tr("project_switched", name=selected["project_name"]), style="green"))
        _show_scope()
        return
    raise ValueError("unsupported project action.")


def _make_report(args: argparse.Namespace) -> None:
    db = get_database()
    scan = db.get_scan(args.scan_id) if args.scan_id is not None else db.latest_scan()
    if not scan:
        console.print(Text(tr("no_scan_report"), style="yellow"))
        return
    observations = db.list_observations(int(scan["id"]))
    ext = "json" if args.format == "json" else "md"
    default_name = f"stari_report_scan{scan['id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    output = Path(args.output) if args.output else Path("reports") / default_name
    written = export_report(scan, observations, output, args.format)
    console.print(Text(f"{tr('report_saved')} {written.resolve()}", style="green"))


def dispatch(argv: list[str], *, interactive: bool = False) -> bool:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        if interactive:
            return True
        raise

    command_name = args.command
    if command_name in {None, "help"}:
        _print_help()
        return True
    if command_name in {"exit", "quit"}:
        return False
    if command_name == "init":
        path = project_dir() / "config.json"
        if path.exists() and not args.force:
            console.print(Text(tr("already_exists"), style="yellow"))
            return True
        config = make_config(args.target, args.name)
        saved = save_config(config)
        Database(project_dir() / "stari.sqlite3")
        init_details = Text()
        init_details.append(tr("project_initialized"), style="green")
        init_details.append("\n\n")
        init_details.append(f"{tr('project')}: {config.project_name}\n")
        init_details.append(f"{tr('target')}: {config.base_url}\n")
        init_details.append(f"{tr('allowed_hosts')}: {config.allowed_hosts[0]}\n")
        init_details.append(f"{tr('config_path')}: {saved}")
        console.print(Panel(init_details, title="stari", border_style="bright_magenta"))
        console.print(tr("authorization_note"))
        return True
    if command_name == "scope":
        _show_scope()
        return True
    if command_name == "recon":
        _run_scan(command_name, extended=bool(args.extended), vuln=bool(args.vuln))
        return True
    if command_name in {"crawl", "endpoints"}:
        _run_scan(
            command_name, crawl_max_pages=args.max_pages,
            crawl_max_scripts=args.max_scripts,
        )
        return True
    if command_name in {"cors", "security"}:
        _run_scan(command_name)
        return True
    if command_name == "diff":
        _show_diff(args.from_scan, args.to_scan)
        return True
    if command_name == "projects":
        _show_projects()
        return True
    if command_name == "project":
        _handle_project_command(args)
        return True
    if command_name == "subdomains":
        _run_scan(
            command_name,
            subdomain_limit=args.limit,
            subdomain_sources=args.source,
        )
        return True
    if command_name == "admin":
        custom_paths = _load_admin_wordlist(args.wordlist)
        _run_scan(
            command_name,
            admin_deep=bool(args.deep),
            admin_custom_paths=custom_paths,
            admin_crawl_pages=int(args.crawl_pages),
            admin_max_paths=args.max_paths,
        )
        return True
    if command_name in {"robots", "sitemap", "headers", "dns", "whois", "tls", "admin", "emails", "ports", "cms", "subdomains", "xss", "sqli", "vuln", "crawl", "endpoints", "cors", "security"}:
        _run_scan(command_name)
        return True
    if command_name == "findings":
        _show_findings(args.scan_id, show_details=args.details)
        return True
    if command_name == "inspect":
        _inspect_observation(args.id)
        return True
    if command_name == "history":
        _show_history()
        return True
    if command_name == "report":
        _make_report(args)
        return True
    parser.print_help()
    return True


def _extract_language_option(argv: list[str]) -> tuple[str | None, list[str]]:
    """Remove --lang option regardless of its position in argv."""
    cleaned: list[str] = []
    selected: str | None = None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--lang":
            if index + 1 >= len(argv):
                raise ValueError("--lang requires 'ru' or 'en'.")
            selected = argv[index + 1]
            index += 2
            continue
        if token.startswith("--lang="):
            selected = token.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(token)
        index += 1
    return selected, cleaned


class StariShell(cmd.Cmd):
    intro = ""

    def __init__(self) -> None:
        super().__init__()
        self.prompt = tr("enter_command")

    def default(self, line: str) -> None:
        try:
            keep_running = dispatch(shlex.split(line), interactive=True)
            if not keep_running:
                return self.do_exit("")
        except (FileNotFoundError, ValueError, OSError) as exc:
            console.print(Text(f"{tr('error')}: {exc}", style="red"))
        except KeyboardInterrupt:
            console.print(f"[yellow]{tr('interrupted')}[/]")

    def emptyline(self) -> None:
        pass

    def do_exit(self, arg: str) -> bool:
        console.print(tr("closed"))
        return True

    def do_EOF(self, arg: str) -> bool:
        console.print()
        return self.do_exit(arg)

    def do_help(self, arg: str) -> None:
        _print_help()


def main(argv: list[str] | None = None) -> None:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        requested_language, command_args = _extract_language_option(raw_args)
        if requested_language is None and command_args in (["--version"], ["-h"], ["--help"]):
            saved = load_saved_language() or "ru"
            choose_language(saved)
        else:
            choose_language(requested_language)
        if not command_args:
            banner()
            try:
                StariShell().cmdloop()
            except KeyboardInterrupt:
                console.print(f"\n{tr('closed')}")
            return
        dispatch(command_args)
    except (FileNotFoundError, ValueError, OSError) as exc:
        console.print(Text(f"{tr('error')}: {exc}", style="red"))
        raise SystemExit(1) from exc
