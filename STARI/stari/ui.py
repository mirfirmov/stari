from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from stari import __version__
from stari.i18n import current_language, tr

console = Console()

ASCII_ART = r""" ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄▄   ▄▄▄▄   ▄▄▄▄▄▄▄   ▄▄▄▄▄
█████▀▀▀ ▀▀▀███▀▀▀ ▄██▀▀██▄ ███▀▀███▄  ███
 ▀████▄     ███    ███  ███ ███▄▄███▀  ███
   ▀████    ███    ███▀▀███ ███▀▀██▄   ███
███████▀    ███    ███  ███ ███  ▀███ ▄███▄"""


def _row_dict(row: dict | Any) -> dict[str, Any]:
    if hasattr(row, "to_dict"):
        return row.to_dict()
    return dict(row)


def banner() -> None:
    art = Text(ASCII_ART, style="bold bright_magenta")
    title = Text(f"s t a r i   cli   v{__version__}", style="bold white", justify="center")
    subtitle = Text(tr("banner_subtitle"), style="dim", justify="center")
    content = Table.grid(padding=(0, 0))
    content.add_row(art)
    content.add_row(Text(""))
    content.add_row(title)
    content.add_row(subtitle)
    console.print(Panel(content, border_style="bright_magenta", padding=(1, 3)))
    console.print(f"[green]{tr('console_ready')}[/]\n")


def observations_table(rows: list[dict] | list, title: str = "observations") -> None:
    table = Table(title=str(title).lower(), header_style="bold bright_magenta", expand=True)
    table.add_column("id", style="dim", no_wrap=True)
    table.add_column(tr("severity"), no_wrap=True)
    table.add_column(tr("status"), no_wrap=True)
    table.add_column(tr("check"), overflow="fold")
    table.add_column(tr("details"), overflow="fold")

    for source_row in rows:
        row = _row_dict(source_row)
        severity = str(row.get("severity", "INFO")).upper()
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}.get(severity, "white")
        table.add_row(
            Text(str(row.get("id", "-"))),
            Text(str(severity).lower(), style=color),
            Text(str(row.get("status", "-")).lower()),
            Text(str(row.get("title", row.get("check_id", "-")).lower())),
            Text(str(row.get("details", "-")).lower()),
        )
    console.print(table)


def key_value_panel(title: str, values: dict[str, object]) -> None:
    table = Table.grid(padding=(0, 2))
    for key, value in values.items():
        table.add_row(Text(str(key).lower(), style="bold"), Text(str(value)))
    console.print(Panel(table, title=title, border_style="bright_magenta"))


def _show_dns_details(rows: list[dict[str, Any]]) -> None:
    record_rows: list[tuple[str, str, str, str, str]] = []
    no_records: list[str] = []
    for row in rows:
        evidence = row.get("evidence") or {}
        no_records.extend(evidence.get("no_records_for_types", []))
        record_type = evidence.get("record_type")
        if not record_type:
            continue
        ttl = str(evidence.get("ttl_seconds", "-"))
        for value in evidence.get("records", []):
            record_rows.append((
                str(record_type), ttl, Text(str(value)),
                Text(str(evidence.get("canonical_name", ""))),
                Text(str(evidence.get("nameserver") or "-")),
            ))
    if record_rows:
        table = Table(title=tr("dns_records_title"), header_style="bold bright_magenta", expand=True)
        table.add_column(tr("dns_type"), no_wrap=True)
        table.add_column(tr("dns_ttl"), justify="right", no_wrap=True)
        table.add_column(tr("dns_value"), overflow="fold")
        table.add_column(tr("dns_canonical_name"), overflow="fold")
        table.add_column(tr("dns_resolver"), overflow="fold")
        for record_type, ttl, value, canonical_name, nameserver in record_rows:
            table.add_row(record_type, ttl, value, canonical_name, nameserver)
        console.print(table)
    if no_records:
        console.print(f"[dim]{tr('dns_no_records_for')}: {', '.join(dict.fromkeys(no_records))}[/]")


def _show_sitemap_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        locations = evidence.get("locations")
        if locations is None:
            continue
        table = Table(title=tr("sitemap_urls_title"), header_style="bold bright_magenta", expand=True)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("url", overflow="fold")
        for index, location in enumerate(locations[:100], start=1):
            table.add_row(str(index), Text(str(location)))
        console.print(table)
        remaining = max(0, len(locations) - 100)
        if remaining:
            console.print(f"[dim]{tr('more_urls', count=remaining)}[/]")


def _show_header_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        headers = evidence.get("response_headers")
        if headers is None:
            continue
        table = Table(title=tr("response_headers_title"), header_style="bold bright_magenta", expand=True)
        table.add_column(tr("http_header"), style="cyan", no_wrap=True)
        table.add_column(tr("http_value"), overflow="fold")
        for item in headers:
            table.add_row(Text(str(item.get("name", ""))), Text(str(item.get("value", ""))))
        panel_title = Text(f"http {evidence.get('http_status', '-')}: {evidence.get('final_url', row.get('target', ''))}")
        console.print(Panel(table, title=panel_title, border_style="bright_magenta"))


def _show_robots_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        content = evidence.get("content")
        if content is None:
            continue
        content = content if content else ("[empty response body]" if current_language() == "en" else "[пустое тело ответа]")
        console.print(Panel(
            Syntax(str(content), "text", theme="ansi_dark", word_wrap=True),
            title=Text(f"robots.txt — {evidence.get('final_url', row.get('target', ''))}"),
            border_style="bright_magenta",
        ))
        parsed_rows = []
        for label in ("user_agent", "allow", "disallow", "sitemap", "crawl_delay", "host"):
            for value in evidence.get(label, []) or []:
                parsed_rows.append((label, str(value)))
        if parsed_rows:
            table = Table(title=tr("robots_directives_title"), header_style="bold bright_magenta", expand=True)
            table.add_column(tr("directive"), style="cyan", no_wrap=True)
            table.add_column(tr("value"), overflow="fold")
            for label, value in parsed_rows:
                table.add_row(Text(label), Text(value))
            console.print(table)


def _show_whois_details(rows: list[dict[str, Any]]) -> None:
    field_keys = (
        "domain_name", "registry_domain_id", "registrar", "registrar_whois_server",
        "registrar_url", "updated_date", "creation_date", "registry_expiry_date",
        "expiration_date", "domain_status", "name_server", "dnssec",
        "network_name", "network_handle", "start_address", "end_address",
        "ip_version", "country", "network_type", "parent_handle", "organization",
        "network_status", "events", "net_range", "cidr", "net_name", "net_handle",
        "parent", "net_type", "org_name", "reg_date", "updated", "origin_as",
    )
    for row in rows:
        evidence = row.get("evidence") or {}
        check_id = str(row.get("check_id", ""))
        if check_id == "WHOIS_SERVER_IP_ADDRESSES":
            addresses = evidence.get("addresses") or []
            table = Table(title=tr("whois_addresses_title"), header_style="bold bright_magenta", expand=True)
            table.add_column("#", style="dim", no_wrap=True)
            table.add_column("ip", style="cyan", overflow="fold")
            table.add_column("version", no_wrap=True)
            for index, address in enumerate(addresses, start=1):
                try:
                    import ipaddress
                    version = f"IPv{ipaddress.ip_address(str(address)).version}"
                except ValueError:
                    version = "-"
                table.add_row(str(index), Text(str(address)), version)
            console.print(table)
            console.print(Panel(tr("whois_edge_note"), border_style="yellow"))
            continue
        if check_id not in {"WHOIS_DOMAIN_REGISTRATION", "WHOIS_IP_REGISTRATION"}:
            continue

        kind = str(evidence.get("lookup_type", "domain"))
        title = tr("whois_domain_title") if kind == "domain" else tr("whois_ip_title")
        metadata = {
            tr("whois_query"): evidence.get("query", "-"),
            tr("whois_source"): evidence.get("source", "-"),
            tr("whois_registry_server"): evidence.get("registry_server") or "rdap bootstrap / authoritative registry",
        }
        key_value_panel(title, metadata)

        fields = evidence.get("fields") or {}
        table = Table(title=tr("whois_field") + " / " + tr("whois_field_value"), header_style="bold bright_magenta", expand=True)
        table.add_column(tr("whois_field"), style="cyan", overflow="fold")
        table.add_column(tr("whois_field_value"), overflow="fold")
        rendered_fields = 0
        for field_key in field_keys:
            value = fields.get(field_key)
            if value in (None, "", [], {}):
                continue
            label = tr(f"whois_{field_key}")
            if isinstance(value, (dict, list)):
                display_value = json.dumps(value, ensure_ascii=False, indent=2, default=str)
            else:
                display_value = str(value)
            table.add_row(Text(label), Text(display_value))
            rendered_fields += 1
        if rendered_fields:
            console.print(table)
        fallback_reason = evidence.get("fallback_reason")
        if fallback_reason:
            console.print(Panel(
                Text(f"{tr('whois_source_note')}\n{fallback_reason}"),
                border_style="dim",
            ))


def _show_tls_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "tls_version" not in evidence:
            continue
        important = {
            tr("tls_version_label"): evidence.get("tls_version"),
            tr("cipher_label"): evidence.get("cipher"),
            tr("cipher_bits_label"): evidence.get("cipher_bits"),
            tr("subject_label"): evidence.get("subject"),
            tr("issuer_label"): evidence.get("issuer"),
            tr("valid_from_label"): evidence.get("valid_from"),
            tr("expires_at_label"): evidence.get("expires_at"),
            tr("days_remaining_label"): evidence.get("days_remaining"),
            tr("fingerprint_label"): evidence.get("sha256_fingerprint"),
        }
        key_value_panel(tr("tls_certificate_details"), important)
        sans = evidence.get("subject_alt_names", [])
        if sans:
            console.print(Panel(Text("\n".join(map(str, sans))), title=tr("tls_san_title"), border_style="bright_magenta"))


def _show_admin_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "candidates" not in evidence:
            continue
        is_ru = current_language() == "ru"

        admin_title = "подтверждённые административные панели" if is_ru else "verified administrative interfaces"
        admin_table = Table(title=admin_title, header_style="bold bright_magenta", expand=True)
        admin_table.add_column("path", overflow="fold")
        admin_table.add_column("source", overflow="fold")
        admin_table.add_column("http", justify="right", no_wrap=True)
        admin_table.add_column("class", overflow="fold")
        admin_table.add_column("confidence", no_wrap=True)
        admin_table.add_column("evidence", overflow="fold")
        admin_table.add_column("final url", overflow="fold")
        for item in evidence.get("candidates", []):
            reasons = "; ".join(map(str, item.get("evidence_reasons", [])))
            aliases = item.get("also_observed_at", [])
            if aliases:
                reasons += "; also observed at: " + ", ".join(str(alias.get("path", "")) for alias in aliases)
            admin_table.add_row(
                Text(str(item.get("path", ""))),
                Text(str(item.get("source", "built-in"))),
                str(item.get("http_status", "")),
                Text(str(item.get("classification", "")).lower()),
                str(item.get("confidence", "")).lower(),
                Text(reasons),
                Text(str(item.get("final_url", ""))),
            )
        if not evidence.get("candidates"):
            empty = "подтверждённых админ-панелей не найдено" if is_ru else "no verified admin panels found"
            admin_table.add_row("—", "—", "—", "—", "—", empty, "—")
        console.print(admin_table)

        login_pages = evidence.get("login_pages", [])
        if login_pages:
            login_title = "обнаруженные страницы входа (роль не подтверждена)" if is_ru else "observed login pages (admin role not confirmed)"
            login_table = Table(title=login_title, header_style="bold cyan", expand=True)
            login_table.add_column("path", overflow="fold")
            login_table.add_column("source", overflow="fold")
            login_table.add_column("http", justify="right", no_wrap=True)
            login_table.add_column("class", overflow="fold")
            login_table.add_column("confidence", no_wrap=True)
            login_table.add_column("evidence", overflow="fold")
            login_table.add_column("final url", overflow="fold")
            for item in login_pages:
                reasons = "; ".join(map(str, item.get("evidence_reasons", [])))
                aliases = item.get("also_observed_at", [])
                if aliases:
                    reasons += "; also observed at: " + ", ".join(str(alias.get("path", "")) for alias in aliases)
                login_table.add_row(
                    Text(str(item.get("path", ""))),
                    Text(str(item.get("source", ""))),
                    str(item.get("http_status", "")),
                    Text(str(item.get("classification", "login_page")).lower()),
                    str(item.get("confidence", "")).lower(),
                    Text(reasons),
                    Text(str(item.get("final_url", ""))),
                )
            console.print(login_table)

        restricted_routes = evidence.get("restricted_routes", [])
        if restricted_routes:
            restricted_title = "ограниченные маршруты (панель не подтверждена)" if is_ru else "restricted routes (admin role not confirmed)"
            restricted_table = Table(title=restricted_title, header_style="bold yellow", expand=True)
            restricted_table.add_column("path", overflow="fold")
            restricted_table.add_column("source", overflow="fold")
            restricted_table.add_column("http", justify="right", no_wrap=True)
            restricted_table.add_column("classification", overflow="fold")
            for item in restricted_routes:
                restricted_table.add_row(
                    Text(str(item.get("path", ""))),
                    Text(str(item.get("source", ""))),
                    str(item.get("http_status", "")),
                    Text(str(item.get("classification", "")).lower()),
                )
            console.print(restricted_table)

        external_redirects = evidence.get("external_redirects", [])
        if external_redirects:
            redirect_title = "внешние перенаправления (адрес назначения не проверялся)" if is_ru else "external redirects (destination not inspected)"
            redirect_table = Table(title=redirect_title, header_style="bold yellow", expand=True)
            redirect_table.add_column("path", overflow="fold")
            redirect_table.add_column("source", overflow="fold")
            redirect_table.add_column("http", justify="right", no_wrap=True)
            redirect_table.add_column("destination", overflow="fold")
            for item in external_redirects:
                redirect_table.add_row(
                    Text(str(item.get("path", ""))),
                    Text(str(item.get("source", ""))),
                    str(item.get("http_status", "")),
                    Text(str(item.get("destination", ""))),
                )
            console.print(redirect_table)

        external_login_links = evidence.get("external_login_links", [])
        if external_login_links:
            link_title = "ссылки на вход вне scope (не проверялись)" if is_ru else "out-of-scope login links (not inspected)"
            link_table = Table(title=link_title, header_style="bold yellow", expand=True)
            link_table.add_column("label", overflow="fold")
            link_table.add_column("host", overflow="fold")
            link_table.add_column("destination", overflow="fold")
            for item in external_login_links:
                link_table.add_row(
                    Text(str(item.get("label", ""))),
                    Text(str(item.get("host", ""))),
                    Text(str(item.get("destination", ""))),
                )
            console.print(link_table)

        related_hosts = evidence.get("related_subdomain_links", [])
        if related_hosts:
            hosts_title = "ссылки на поддомены вне scope (не проверялись)" if is_ru else "linked subdomains outside scope (not inspected)"
            hosts_table = Table(title=hosts_title, header_style="bold cyan", expand=True)
            hosts_table.add_column("host", overflow="fold")
            hosts_table.add_column("link text", overflow="fold")
            hosts_table.add_column("path", overflow="fold")
            for item in related_hosts:
                hosts_table.add_row(
                    Text(str(item.get("host", ""))),
                    Text(str(item.get("label", ""))),
                    Text(str(item.get("path", ""))),
                )
            console.print(hosts_table)

        robots_hint_count = int(evidence.get("robots_admin_path_hint_count", 0))
        robots_status = evidence.get("robots_http_status")
        robots_label = (
            f"подсказок путей из robots.txt: {robots_hint_count} (http {robots_status if robots_status is not None else 'нет ответа'}); сами подсказки не считаются найденными страницами"
            if is_ru else
            f"robots.txt path hints: {robots_hint_count} (http {robots_status if robots_status is not None else 'no response'}); hints are not counted as found pages"
        )
        console.print(Text(robots_label, style="dim"))

        summary = (
            f"проверено кандидатов: {evidence.get('checked_paths', 0)} | "
            f"подтверждено админ-панелей: {evidence.get('verified_count', evidence.get('candidate_count', 0))} | "
            f"страниц входа: {evidence.get('login_page_count', 0)} | "
            f"ссылок на вход вне scope: {len(external_login_links)} | "
            f"поддоменов вне scope: {len(related_hosts)} | "
            f"soft 404 исключено: {evidence.get('soft_404_filtered', 0)} | "
            f"401/403 без подтверждения: {evidence.get('restricted_unverified_count', 0)} | "
            f"неоднозначных ответов исключено: {evidence.get('weak_signal_ignored_count', 0)} | "
            f"страниц исследовано: {evidence.get('pages_crawled', 0)} | js: {evidence.get('javascript_assets_inspected', 0)}"
            if is_ru else
            f"candidates checked: {evidence.get('checked_paths', 0)} | "
            f"verified admin panels: {evidence.get('verified_count', evidence.get('candidate_count', 0))} | "
            f"login pages: {evidence.get('login_page_count', 0)} | "
            f"out-of-scope login links: {len(external_login_links)} | "
            f"out-of-scope subdomains: {len(related_hosts)} | "
            f"soft 404 filtered: {evidence.get('soft_404_filtered', 0)} | "
            f"401/403 without confirmation: {evidence.get('restricted_unverified_count', 0)} | "
            f"ambiguous responses ignored: {evidence.get('weak_signal_ignored_count', 0)} | "
            f"pages inspected: {evidence.get('pages_crawled', 0)} | js: {evidence.get('javascript_assets_inspected', 0)}"
        )
        console.print(Text(summary, style="dim"))
        if not evidence.get("baseline_stable"):
            warning = (
                "контрольные url нестабильны: обнаруженные страницы входа показаны отдельно и не повышены до подтверждённых админ-панелей."
                if is_ru else
                "control urls were unstable: observed login pages are listed separately and are not promoted to verified admin panels."
            )
            console.print(Text(warning, style="yellow"))


def _show_email_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "emails" not in evidence:
            continue
        title = "публичные email" if current_language() == "ru" else "public email addresses"
        table = Table(title=title, header_style="bold bright_magenta", expand=True)
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("email", style="cyan", overflow="fold")
        for index, email in enumerate(evidence.get("emails", []), start=1):
            table.add_row(str(index), Text(str(email)))
        if not evidence.get("emails"):
            table.add_row("—", "не найдено" if current_language() == "ru" else "none found")
        console.print(table)


def _show_port_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "ports" not in evidence:
            continue
        title = "tcp-порты веб-служб" if current_language() == "ru" else "web tcp ports"
        table = Table(title=title, header_style="bold bright_magenta", expand=True)
        table.add_column("port", justify="right", no_wrap=True)
        table.add_column("state", no_wrap=True)
        table.add_column("service hint")
        for item in evidence.get("ports", []):
            state = str(item.get("state", ""))
            color = "green" if str(state).upper() == "OPEN" else "dim"
            table.add_row(str(item.get("port", "")), Text(str(state).lower(), style=color), Text(str(item.get("service_hint", ""))))
        console.print(table)


def _show_cms_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "detected" not in evidence:
            continue
        title = "обнаруженные cms / платформы" if current_language() == "ru" else "detected cms / platforms"
        table = Table(title=title, header_style="bold bright_magenta", expand=True)
        table.add_column("platform", style="cyan")
        table.add_column(tr("cms_confidence"), justify="right", no_wrap=True)
        table.add_column(tr("cms_level"), no_wrap=True)
        table.add_column("signals", overflow="fold")
        for item in evidence.get("detected", []):
            table.add_row(
                Text(str(item.get("name", ""))),
                f"{item.get('confidence', 0)}%",
                Text(str(item.get("confidence_level", "")).lower()),
                Text(", ".join(map(str, item.get("signals", [])))),
            )
        if not evidence.get("detected"):
            table.add_row("—", "не определено" if current_language() == "ru" else "not identified")
        console.print(table)
        technologies = evidence.get("technologies", [])
        if technologies:
            tech_table = Table(title=tr("technologies_title"), header_style="bold bright_magenta", expand=True)
            tech_table.add_column("technology", style="cyan")
            tech_table.add_column(tr("cms_confidence"), justify="right")
            tech_table.add_column("signals", overflow="fold")
            for item in technologies:
                tech_table.add_row(
                    Text(str(item.get("name", ""))),
                    f"{item.get('confidence', 0)}%",
                    Text(", ".join(map(str, item.get("signals", [])))),
                )
            console.print(tech_table)
        if evidence.get("server_header") or evidence.get("x_powered_by"):
            key_value_panel("http fingerprint", {
                "server": evidence.get("server_header") or "—",
                "x-powered-by": evidence.get("x_powered_by") or "—",
            })


def _show_crawler_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "pages_visited" not in evidence:
            continue
        pages = evidence.get("pages_visited", [])
        page_table = Table(title=tr("crawler_pages_title"), header_style="bold bright_magenta", expand=True)
        page_table.add_column("http", justify="right", no_wrap=True)
        page_table.add_column("url", overflow="fold")
        page_table.add_column("title", overflow="fold")
        for item in pages:
            status = int(item.get("status", 0))
            color = "green" if 200 <= status < 300 else "yellow" if 300 <= status < 400 else "red"
            page_table.add_row(Text(str(status), style=color), Text(str(item.get("url", ""))), Text(str(item.get("title", ""))))
        if not pages:
            page_table.add_row("—", tr("crawler_empty"), "")
        console.print(page_table)

        forms = evidence.get("forms", [])
        if forms:
            form_table = Table(title=tr("crawler_forms_title"), header_style="bold bright_magenta", expand=True)
            form_table.add_column("method", no_wrap=True)
            form_table.add_column("action", overflow="fold")
            form_table.add_column("field names", overflow="fold")
            for item in forms:
                form_table.add_row(
                    str(item.get("method", "get")), Text(str(item.get("action", ""))),
                    Text(", ".join(map(str, item.get("field_names", [])))),
                )
            console.print(form_table)

        endpoints = evidence.get("api_endpoints", [])
        if endpoints:
            endpoint_table = Table(title=tr("crawler_endpoints_title"), header_style="bold bright_magenta", expand=True)
            endpoint_table.add_column("endpoint", overflow="fold")
            for endpoint in endpoints:
                endpoint_table.add_row(Text(str(endpoint)))
            console.print(endpoint_table)

        scripts = evidence.get("scripts", [])
        if scripts:
            script_table = Table(title=tr("crawler_scripts_title"), header_style="bold bright_magenta", expand=True)
            script_table.add_column("javascript", overflow="fold")
            for script in scripts:
                script_table.add_row(Text(str(script)))
            console.print(script_table)
        limitations = evidence.get("limitations", [])
        if limitations:
            note = "\n".join(f"• {item}" for item in limitations)
            console.print(Panel(Text(note), title="crawler limits", border_style="dim"))


def _show_cors_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "access_control_allow_origin" not in evidence and row.get("check_id") != "CORS_CONFIGURATION_REVIEW":
            continue
        values = {
            "http status": evidence.get("http_status", "—"),
            "access-control-allow-origin": evidence.get("access_control_allow_origin") or "—",
            "access-control-allow-credentials": evidence.get("access_control_allow_credentials", False),
            "vary: origin": evidence.get("vary_origin", False),
            "credentials sent": evidence.get("credentials_sent", False),
        }
        key_value_panel(tr("cors_title"), values)


def _show_subdomain_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        if "subdomains" not in evidence or "base_domain" not in evidence:
            continue
        title = "найденные поддомены (пассивный поиск)" if current_language() == "ru" else "discovered subdomains (passive search)"
        table = Table(title=title, header_style="bold bright_magenta", expand=True)
        table.add_column("hostname", style="cyan", overflow="fold")
        table.add_column("sources", overflow="fold")
        names = evidence.get("subdomains", [])
        for item in names:
            table.add_row(
                Text(str(item.get("hostname", ""))),
                Text(", ".join(map(str, item.get("sources", []))) or "—"),
            )
        if not names:
            table.add_row("—", "ничего не найдено" if current_language() == "ru" else "no names found")
        console.print(table)

        source_results = evidence.get("source_results", {})
        if source_results:
            status_table = Table(
                title="источники" if current_language() == "ru" else "source status",
                header_style="bold bright_magenta", expand=True,
            )
            status_table.add_column("source", style="cyan")
            status_table.add_column("status", no_wrap=True)
            status_table.add_column("names", justify="right")
            status_table.add_column("note", overflow="fold")
            for source, result in source_results.items():
                status_table.add_row(
                    Text(str(source)), str(result.get("status", "-")).lower(),
                    str(result.get("count", 0)), Text(str(result.get("error") or "—").lower()),
                )
            console.print(status_table)

        if current_language() == "ru":
            console.print(
                "[dim]Это пассивный поиск по публичным индексам. STARI не перебирает имена, "
                "не отправляет dns-запросы к найденным хостам и не подключается к ним. "
                "часть записей может быть исторической; актуальность dns отдельно не проверялась.[/]"
            )
        else:
            console.print(
                "[dim]Passive public-index search only. STARI does not guess labels, "
                "resolve discovered hosts, or connect to them. some records may be historical; "
                "current dns status is not checked.[/]"
            )


def _show_vulnerability_details(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        evidence = row.get("evidence") or {}
        check_id = str(row.get("check_id", ""))
        if check_id == "XSS_REFLECTION_CHECK":
            results = evidence.get("results", [])
            title = "проверка отражённого xss" if current_language() == "ru" else "reflected xss check"
            table = Table(title=title, header_style="bold bright_magenta", expand=True)
            table.add_column("endpoint", overflow="fold")
            table.add_column("parameter", no_wrap=True)
            table.add_column("classification", overflow="fold")
            table.add_column("http", justify="right")
            for item in results:
                table.add_row(Text(str(item.get("endpoint", ""))), Text(str(item.get("parameter", ""))),
                              Text(str(item.get("classification", "")).lower()), str(item.get("http_status", "")))
            if not results:
                table.add_row("—", "—", "no reflection observed" if current_language() == "en" else "Отражение не обнаружено", "—")
            console.print(table)
            if current_language() == "ru":
                console.print("[yellow]HTML-маркер не исполняет JavaScript. Результат требует ручной проверки контекста.[/]")
            else:
                console.print("[yellow]The HTML canary does not execute JavaScript. Manually validate the output context.[/]")
        elif check_id == "SQLI_HEURISTIC_CHECK":
            findings = evidence.get("findings", [])
            title = "эвристическая проверка sql-инъекций" if current_language() == "ru" else "sql injection heuristic check"
            table = Table(title=title, header_style="bold bright_magenta", expand=True)
            table.add_column("endpoint", overflow="fold")
            table.add_column("parameter", no_wrap=True)
            table.add_column("signals", overflow="fold")
            for item in findings:
                table.add_row(Text(str(item.get("endpoint", ""))), Text(str(item.get("parameter", ""))),
                              Text(", ".join(map(str, item.get("signals", [])))))
            if not findings:
                table.add_row("—", "—", "no sqli signal" if current_language() == "en" else "Признаков SQLi нет")
            console.print(table)
            if current_language() == "ru":
                console.print("[yellow]Эвристические признаки не подтверждают SQL-инъекцию. Временные и изменяющие данные запросы не выполнялись.[/]")
            else:
                console.print("[yellow]Heuristic signals do not confirm SQL injection. No time-delay or data-changing probes were sent.[/]")

def render_scan_details(mode: str, observations: list[dict] | list) -> None:
    """Render useful evidence immediately after each scan command."""
    rows = [_row_dict(item) for item in observations]
    is_recon = mode.startswith("recon")
    is_extended = "extended" in mode
    is_vuln = "vuln" in mode or mode == "vuln"
    if mode == "dns" or is_recon:
        _show_dns_details(rows)
    if mode == "sitemap" or is_recon:
        _show_sitemap_details(rows)
    if mode == "headers" or mode == "security" or is_recon:
        _show_header_details(rows)
    if mode == "cors" or mode == "security" or is_recon:
        _show_cors_details(rows)
    if mode == "robots" or is_recon:
        _show_robots_details(rows)
    if mode == "tls" or is_recon:
        _show_tls_details(rows)
    if mode == "whois" or is_recon:
        _show_whois_details(rows)
    if mode == "subdomains" or (is_recon and is_extended):
        _show_subdomain_details(rows)
    if mode == "admin" or (is_recon and is_extended):
        _show_admin_details(rows)
    if mode == "emails" or (is_recon and is_extended):
        _show_email_details(rows)
    if mode == "ports" or (is_recon and is_extended):
        _show_port_details(rows)
    if mode == "cms" or (is_recon and is_extended):
        _show_cms_details(rows)
    if mode in {"crawl", "endpoints"} or (is_recon and is_extended):
        _show_crawler_details(rows)
    if mode in {"xss", "sqli", "vuln"} or (is_recon and is_vuln):
        _show_vulnerability_details(rows)

def render_observation_detail(row: dict[str, Any]) -> None:
    evidence = row.get("evidence") or {}
    details = Text()
    details.append(str(row.get("title", "observation")).lower(), style="bold")
    details.append("\n")
    details.append(f"id: {row.get('id', '-')} | check: {row.get('check_id', '-')}\n")
    details.append(f"scan: {row.get('scan_id', '-')} | mode: {row.get('scan_mode', '-')}\n")
    details.append(f"{tr('severity')}: {str(row.get('severity', '-')).lower()} | {tr('status')}: {str(row.get('status', '-')).lower()}\n")
    details.append(f"{tr('target')}: {row.get('target', '-')}\n\n")
    details.append(str(row.get("details", "")).lower())
    console.print(Panel(details, title=Text(f"{tr('observation')} #{row.get('id', '-') }"), border_style="bright_magenta"))
    if evidence:
        console.print(Panel(
            Syntax(json.dumps(evidence, indent=2, ensure_ascii=False, default=str), "json", theme="ansi_dark", word_wrap=True),
            title=tr("evidence"), border_style="bright_magenta",
        ))
