from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable

SUPPORTED_LANGUAGES = {"ru", "en"}
_DEFAULT_LANGUAGE = "ru"
_LANGUAGE = _DEFAULT_LANGUAGE

MESSAGES: dict[str, dict[str, str]] = {
    "ru": {
        "language_title": "Выберите язык / Select language",
        "scan_id_arg": "ID сохранённой проверки",
        "show_evidence_arg": "Показать полные доказательства",
        "help_commands": "Показать список команд",
        "user_agent": "User-Agent",
        "timeout": "Тайм-аут",
        "timeout_value": "{value} секунд",
        "observation_missing_any": "Результат #{id} не найден ни в одной сохранённой проверке.",
        "dns_records_title": "DNS-записи",
        "dns_type": "Тип",
        "dns_ttl": "TTL (сек.)",
        "dns_value": "Значение",
        "dns_canonical_name": "Каноническое имя",
        "dns_resolver": "DNS-сервер",
        "dns_no_records_for": "Записей нет для типов",
        "whois_domain_title": "Регистрационные данные домена",
        "whois_ip_title": "Регистрационные данные IP-сети",
        "whois_addresses_title": "IP-адреса, опубликованные в DNS",
        "whois_query": "Запрос",
        "whois_source": "Источник данных",
        "whois_registry_server": "Сервер реестра",
        "whois_field": "Поле",
        "whois_field_value": "Значение",
        "whois_edge_note": "Это IP-адреса из текущих DNS-ответов. При использовании CDN, reverse proxy или балансировщика здесь могут отображаться edge-адреса, а не origin-сервер.",
        "whois_source_note": "WHOIS используется первым; при недоступности или неполном ответе применяется RDAP.",
        "whois_skipped_private": "Непубличные адреса не отправляются в реестры.",
        "whois_domain_name": "Домен",
        "whois_registry_domain_id": "ID домена в реестре",
        "whois_registrar": "Регистратор",
        "whois_registrar_whois_server": "WHOIS-сервер регистратора",
        "whois_registrar_url": "Сайт регистратора",
        "whois_updated_date": "Дата обновления",
        "whois_creation_date": "Дата регистрации",
        "whois_registry_expiry_date": "Окончание регистрации",
        "whois_expiration_date": "Дата истечения",
        "whois_domain_status": "Статус домена",
        "whois_name_server": "DNS-серверы",
        "whois_dnssec": "DNSSEC",
        "whois_network_name": "Название сети",
        "whois_network_handle": "ID сети",
        "whois_start_address": "Начальный IP",
        "whois_end_address": "Конечный IP",
        "whois_ip_version": "Версия IP",
        "whois_country": "Страна",
        "whois_network_type": "Тип сети",
        "whois_parent_handle": "Родительский блок",
        "whois_organization": "Организация",
        "whois_network_status": "Статус сети",
        "whois_events": "События регистрации",
        "whois_net_range": "Диапазон сети",
        "whois_cidr": "CIDR",
        "whois_net_name": "Название блока",
        "whois_net_handle": "ID блока",
        "whois_parent": "Родительский блок",
        "whois_net_type": "Тип блока",
        "whois_org_name": "Организация",
        "whois_reg_date": "Дата регистрации сети",
        "whois_updated": "Дата обновления сети",
        "whois_origin_as": "Origin ASN",
        "sitemap_urls_title": "URL из sitemap.xml (только разрешённая область)",
        "more_urls": "И ещё URL: {count}. Полный список сохранён в базе и отчёте.",
        "response_headers_title": "HTTP-заголовки ответа",
        "robots_directives_title": "Распознанные директивы robots.txt",
        "directive": "Директива",
        "value": "Значение",
        "tls_certificate_details": "Данные TLS-сертификата",
        "tls_san_title": "Альтернативные имена сертификата (SAN)",
        "http_header": "Заголовок",
        "http_value": "Значение",
        "tls_version_label": "Версия TLS",
        "cipher_label": "Шифр",
        "cipher_bits_label": "Длина ключа шифра",
        "subject_label": "Subject",
        "issuer_label": "Issuer",
        "valid_from_label": "Действителен с",
        "expires_at_label": "Истекает",
        "days_remaining_label": "Дней до истечения",
        "fingerprint_label": "SHA-256 fingerprint",
        "language_ru": "Русский",
        "language_en": "Английский",
        "language_saved": "Язык интерфейса: {language}",
        "app_description": "STARI CLI — консольный инструмент разведки безопасности веб-приложений",
        "target_arg": "Домен или базовый URL, например https://example.com",
        "name_arg": "Необязательное название проекта",
        "force_arg": "Заменить текущую конфигурацию проекта",
        "format_arg": "Формат отчёта",
        "output_arg": "Путь к выходному файлу",
        "banner_subtitle": "ИНСТРУМЕНТ РАЗВЕДКИ И АНАЛИЗА БЕЗОПАСНОСТИ ВЕБ-ПРИЛОЖЕНИЙ",
        "console_ready": "Консоль готова. Введите help для списка команд.",
        "commands_title": "Команды STARI",
        "command": "Команда",
        "description": "Описание",
        "help_init": "Создать проект и задать разрешённую область проверки",
        "help_scope": "Показать настроенную область проверки",
        "help_recon": "Запустить базовые проверки разведки",
        "help_robots": "Проверить robots.txt",
        "help_sitemap": "Проверить sitemap.xml",
        "help_headers": "Проверить HTTP-заголовки ответа",
        "help_dns": "Получить DNS-записи хоста",
        "help_whois": "Получить WHOIS/RDAP домена и IP-адресов из DNS",
        "help_tls": "Проверить TLS-сертификат",
        "help_admin": "Найти административные интерфейсы и реальные страницы входа",
        "admin_deep_help": "Добавить расширенный набор маршрутов (больше GET-запросов)",
        "admin_max_paths_help": "Максимум кандидатов: 1–600; по умолчанию 320",
        "admin_crawl_pages_help": "Максимум внутренних HTML-страниц для поиска ссылок: 0–40",
        "admin_wordlist_help": "Дополнительный UTF-8 файл путей, максимум 1000 строк",
        "help_emails": "Найти публично опубликованные email на страницах сайта",
        "help_ports": "Проверить ограниченный список веб TCP-портов",
        "help_cms": "Определить CMS и веб-платформу",
        "help_subdomains": "Пассивно искать поддомены в публичных OSINT-индексах без DNS-проверки",
        "subdomains_limit_help": "Максимум показываемых уникальных имён: от 1 до 5000; по умолчанию 500",
        "subdomains_source_help": "Источник: crtsh, certspotter, hackertarget, otx, urlscan или wayback (можно повторять)",
        "help_xss": "Проверить GET-параметры на небезопасное отражение HTML-маркера",
        "help_sqli": "Проверить GET-параметры на SQL-ошибки и boolean-differential",
        "help_vuln": "Запустить эвристические проверки XSS и SQLi",
        "help_recon_vuln": "Добавить ограниченные проверки XSS и SQLi",
        "help_recon_extended": "Добавить поддомены, admin finder, email, порты и CMS",
        "help_findings": "Показать результаты последней проверки",
        "help_inspect": "Показать подробности результата и доказательства",
        "help_history": "Показать историю проверок",
        "help_report": "Экспортировать отчёт последней проверки",
        "help_crawl": "Обойти страницы в разрешённой области и собрать формы, JS и API-маршруты",
        "help_endpoints": "Построить инвентарь URL и API-маршрутов",
        "help_cors": "Проверить CORS с тестовым Origin без отправки credentials",
        "help_security": "Проверить security headers, cookies и CORS",
        "crawl_pages_help": "Максимум HTML-страниц: 1–500 (по умолчанию 100)",
        "crawl_scripts_help": "Максимум JS-файлов: 0–100 (по умолчанию 30)",
        "help_diff": "Сравнить результаты двух сканирований",
        "diff_from_help": "ID предыдущего сканирования",
        "diff_to_help": "ID нового сканирования; по умолчанию последнее",
        "diff_title": "Сравнение сканирований #{before} → #{after}",
        "diff_state": "Изменение",
        "diff_before": "До",
        "diff_after": "После",
        "diff_new": "Новое",
        "diff_resolved": "Исчезло",
        "diff_changed": "Изменилось",
        "diff_unchanged": "Без изменений",
        "diff_scan_missing": "Сканирование #{id} не найдено.",
        "diff_no_target": "Нет второго сканирования для сравнения.",
        "diff_same_scan": "Нельзя сравнить сканирование само с собой.",
        "diff_target_mismatch": "Цели отличаются: {before} и {after}. Сравнение отменено.",
        "help_project": "Управлять отдельными проектами",
        "help_project_add": "Создать отдельный проект",
        "help_project_switch": "Переключить активный проект",
        "help_project_list": "Показать все проекты",
        "help_project_current": "Показать активный проект",
        "project_identifier_help": "Название или slug проекта",
        "projects_title": "Проекты STARI",
        "project_active": "АКТИВЕН",
        "no_projects": "Проекты не найдены. Сначала выполните init.",
        "project_added": "Проект '{name}' создан (slug: {slug}) и активирован.",
        "project_switched": "Активный проект: {name}",
        "crawler_pages_title": "Страницы, обнаруженные краулером",
        "crawler_forms_title": "HTML-формы (не отправлялись)",
        "crawler_endpoints_title": "API и интересные endpoint-маршруты",
        "crawler_scripts_title": "Внутренние JavaScript-файлы",
        "crawler_empty": "Не найдено",
        "cors_title": "Аудит CORS",
        "cms_confidence": "Достоверность",
        "cms_level": "Уровень",
        "technologies_title": "Обнаруженные технологии",
        "language_change_help": "Чтобы сменить язык, перезапустите start.bat --lang ru/en или ./start.sh --lang ru/en.",
        "help_exit": "Выйти из консоли",
        "target": "Цель",
        "scope_limited": "Область проверки ограничена; частота запросов регулируется.",
        "completed": "Завершено. Сохранено наблюдений: {count}. База данных SQLite.",
        "project_scope": "Область проекта",
        "project": "Проект",
        "base_url": "Основной URL",
        "allowed_hosts": "Разрешённые хосты",
        "request_rate": "Частота запросов",
        "response_cap": "Лимит размера ответа",
        "no_scans": "Проверок пока нет. Сначала выполните recon.",
        "no_scan_history": "История проверок пока пуста.",
        "no_scan_report": "Нет отчёта. Сначала выполните recon.",
        "observation_missing": "Результат #{id} не найден в последней проверке.",
        "scan_history": "История проверок",
        "scan_id": "ID",
        "mode": "Режим",
        "started": "Начало",
        "observations": "Наблюдения",
        "severity": "Важность",
        "status": "Статус",
        "check": "Проверка",
        "details": "Подробности",
        "report_saved": "Отчёт сохранён:",
        "already_exists": "Проект уже существует. Используйте 'init --force' для замены конфигурации.",
        "project_initialized": "Проект создан.",
        "config_path": "Конфигурация",
        "authorization_note": "Проверяйте только системы, которыми владеете или на проверку которых получили разрешение.",
        "error": "Ошибка",
        "interrupted": "\nКоманда прервана.",
        "closed": "STARI закрыт.",
        "observation": "Результат",
        "evidence": "Доказательства",
        "scan": "проверка",
        "enter_command": "stari> ",
        "language_change_help": "Чтобы сменить язык, перезапустите start.bat --lang ru или start.bat --lang en.",
        "target_empty": "Цель не может быть пустой.",
        "scheme_unsupported": "Поддерживаются только схемы http:// и https://.",
        "hostname_missing": "В целевом URL должно быть указано имя хоста.",
        "credentials_disallowed": "Логин и пароль в целевом URL не допускаются.",
        "query_fragment_disallowed": "Укажите базовый URL без query-параметров и fragment.",
        "path_disallowed": "Для этой версии укажите домен или origin без пути.",
        "invalid_hostname": "Некорректное имя хоста.",
        "project_not_initialized": "Проект STARI не создан. Выполните: stari init --target example.com",
        "out_of_scope": "URL вне разрешённой области проверки заблокирован: {url}",
        "request_rate_value": "{value} запрос(ов)/сек",
        "response_cap_value": "{value} байт",
    },
    "en": {
        "language_title": "Select language / Выберите язык",
        "scan_id_arg": "ID of a saved scan",
        "show_evidence_arg": "Display full evidence details",
        "help_commands": "Show available commands",
        "user_agent": "User-Agent",
        "timeout": "Timeout",
        "timeout_value": "{value} seconds",
        "observation_missing_any": "Observation #{id} was not found in any saved scan.",
        "dns_records_title": "DNS records",
        "dns_type": "Type",
        "dns_ttl": "TTL (sec)",
        "dns_value": "Value",
        "dns_canonical_name": "Canonical name",
        "dns_resolver": "Resolver",
        "dns_no_records_for": "No records for types",
        "whois_domain_title": "Domain registration data",
        "whois_ip_title": "IP network registration data",
        "whois_addresses_title": "IP addresses published in DNS",
        "whois_query": "Query",
        "whois_source": "Data source",
        "whois_registry_server": "Registry server",
        "whois_field": "Field",
        "whois_field_value": "Value",
        "whois_edge_note": "These are IP addresses from current DNS answers. With a CDN, reverse proxy, or load balancer, they may be edge addresses rather than the origin server.",
        "whois_source_note": "WHOIS is attempted first; RDAP is used when WHOIS is unavailable or incomplete.",
        "whois_skipped_private": "Non-public addresses are not sent to registration services.",
        "whois_domain_name": "Domain",
        "whois_registry_domain_id": "Registry domain ID",
        "whois_registrar": "Registrar",
        "whois_registrar_whois_server": "Registrar WHOIS server",
        "whois_registrar_url": "Registrar URL",
        "whois_updated_date": "Updated date",
        "whois_creation_date": "Creation date",
        "whois_registry_expiry_date": "Registry expiry date",
        "whois_expiration_date": "Expiration date",
        "whois_domain_status": "Domain status",
        "whois_name_server": "Name servers",
        "whois_dnssec": "DNSSEC",
        "whois_network_name": "Network name",
        "whois_network_handle": "Network handle",
        "whois_start_address": "Start address",
        "whois_end_address": "End address",
        "whois_ip_version": "IP version",
        "whois_country": "Country",
        "whois_network_type": "Network type",
        "whois_parent_handle": "Parent block",
        "whois_organization": "Organization",
        "whois_network_status": "Network status",
        "whois_events": "Registration events",
        "whois_net_range": "Network range",
        "whois_cidr": "CIDR",
        "whois_net_name": "Network block name",
        "whois_net_handle": "Network block handle",
        "whois_parent": "Parent block",
        "whois_net_type": "Network block type",
        "whois_org_name": "Organization",
        "whois_reg_date": "Network registration date",
        "whois_updated": "Network updated date",
        "whois_origin_as": "Origin ASN",
        "sitemap_urls_title": "URLs from sitemap.xml (in-scope only)",
        "more_urls": "And {count} more URLs. The full list is saved in the database and report.",
        "response_headers_title": "HTTP response headers",
        "robots_directives_title": "Parsed robots.txt directives",
        "directive": "Directive",
        "value": "Value",
        "tls_certificate_details": "TLS certificate details",
        "tls_san_title": "Subject Alternative Names",
        "http_header": "Header",
        "http_value": "Value",
        "tls_version_label": "TLS version",
        "cipher_label": "Cipher",
        "cipher_bits_label": "Cipher bits",
        "subject_label": "Subject",
        "issuer_label": "Issuer",
        "valid_from_label": "Valid from",
        "expires_at_label": "Expires at",
        "days_remaining_label": "Days remaining",
        "fingerprint_label": "SHA-256 fingerprint",
        "language_ru": "Russian",
        "language_en": "English",
        "language_saved": "Interface language: {language}",
        "app_description": "STARI CLI - console-first web application security reconnaissance toolkit",
        "target_arg": "Domain or base URL, e.g. https://example.com",
        "name_arg": "Optional project name",
        "force_arg": "Replace the current project configuration",
        "format_arg": "Report format",
        "output_arg": "Output file path",
        "banner_subtitle": "WEB APPLICATION SECURITY RECONNAISSANCE TOOLKIT",
        "console_ready": "Console ready. Type help to see available commands.",
        "commands_title": "STARI commands",
        "command": "Command",
        "description": "Description",
        "help_init": "Initialize a project and define its allowed scope",
        "help_scope": "Show the configured target scope",
        "help_recon": "Run baseline reconnaissance checks",
        "help_robots": "Inspect robots.txt",
        "help_sitemap": "Inspect sitemap.xml",
        "help_headers": "Inspect HTTP response headers",
        "help_dns": "Resolve DNS records for the host",
        "help_whois": "Look up WHOIS/RDAP data for the domain and DNS IPs",
        "help_tls": "Inspect the TLS certificate",
        "help_admin": "Discover administrative interfaces and real login pages",
        "admin_deep_help": "Add the extended route catalogue (increases GET requests)",
        "admin_max_paths_help": "Maximum candidate paths: 1–600; default: 320",
        "admin_crawl_pages_help": "Maximum same-origin HTML pages to inspect: 0–40",
        "admin_wordlist_help": "Additional UTF-8 path list; up to 1,000 lines",
        "help_emails": "Find publicly published email addresses on site pages",
        "help_ports": "Check a limited list of web TCP ports",
        "help_cms": "Identify CMS and web platform",
        "help_subdomains": "Passively discover subdomains from public OSINT indexes without DNS checks",
        "subdomains_limit_help": "Maximum unique names displayed: 1–5000; default: 500",
        "subdomains_source_help": "Source: crtsh, certspotter, hackertarget, otx, urlscan or wayback (repeatable)",
        "help_xss": "Check GET parameters for unsafe reflection of an HTML canary",
        "help_sqli": "Check GET parameters for SQL errors and boolean differentials",
        "help_vuln": "Run heuristic XSS and SQLi checks",
        "help_recon_vuln": "Include bounded XSS and SQLi checks",
        "help_recon_extended": "Include subdomains, admin finder, email, ports and CMS",
        "help_findings": "Show observations from the latest scan",
        "help_inspect": "Show observation details and evidence",
        "help_history": "Show scan history",
        "help_report": "Export the latest scan report",
        "help_crawl": "Crawl in-scope pages and inventory forms, JavaScript and API routes",
        "help_endpoints": "Build an inventory of URLs and API routes",
        "help_cors": "Review CORS with a synthetic Origin and no credentials",
        "help_security": "Audit security headers, cookies and CORS",
        "crawl_pages_help": "Maximum HTML pages: 1–500 (default 100)",
        "crawl_scripts_help": "Maximum JavaScript files: 0–100 (default 30)",
        "help_diff": "Compare two saved scans",
        "diff_from_help": "ID of the earlier scan",
        "diff_to_help": "ID of the newer scan; defaults to latest",
        "diff_title": "Scan comparison #{before} → #{after}",
        "diff_state": "Change",
        "diff_before": "Before",
        "diff_after": "After",
        "diff_new": "New",
        "diff_resolved": "Resolved",
        "diff_changed": "Changed",
        "diff_unchanged": "Unchanged",
        "diff_scan_missing": "Scan #{id} was not found.",
        "diff_no_target": "No second scan is available for comparison.",
        "diff_same_scan": "A scan cannot be compared with itself.",
        "diff_target_mismatch": "Targets differ: {before} and {after}. Comparison cancelled.",
        "help_project": "Manage separate projects",
        "help_project_add": "Create a separate project",
        "help_project_switch": "Switch the active project",
        "help_project_list": "List all projects",
        "help_project_current": "Show the active project",
        "project_identifier_help": "Project name or slug",
        "projects_title": "STARI projects",
        "project_active": "ACTIVE",
        "no_projects": "No projects found. Run init first.",
        "project_added": "Project '{name}' created (slug: {slug}) and activated.",
        "project_switched": "Active project: {name}",
        "crawler_pages_title": "Pages discovered by crawler",
        "crawler_forms_title": "HTML forms (not submitted)",
        "crawler_endpoints_title": "API and interesting endpoint routes",
        "crawler_scripts_title": "In-scope JavaScript files",
        "crawler_empty": "None found",
        "cors_title": "CORS audit",
        "cms_confidence": "Confidence",
        "cms_level": "Level",
        "technologies_title": "Detected technologies",
        "language_change_help": "Restart with start.bat --lang ru/en or ./start.sh --lang ru/en to change language.",
        "help_exit": "Exit the console",
        "target": "Target",
        "scope_limited": "Scope restriction active; request rate is limited.",
        "completed": "Completed. Saved {count} observations to SQLite.",
        "project_scope": "Project scope",
        "project": "Project",
        "base_url": "Base URL",
        "allowed_hosts": "Allowed hosts",
        "request_rate": "Request rate",
        "response_cap": "Response size cap",
        "no_scans": "No scans recorded yet. Run 'recon' first.",
        "no_scan_history": "No scan history yet.",
        "no_scan_report": "No scan available. Run 'recon' first.",
        "observation_missing": "Observation #{id} was not found in the latest scan.",
        "scan_history": "Scan history",
        "scan_id": "ID",
        "mode": "Mode",
        "started": "Started",
        "observations": "Observations",
        "severity": "Severity",
        "status": "Status",
        "check": "Check",
        "details": "Details",
        "report_saved": "Report saved:",
        "already_exists": "Project already exists. Use 'init --force' to replace its configuration.",
        "project_initialized": "Project initialized.",
        "config_path": "Config",
        "authorization_note": "Only assess systems you own or are explicitly authorized to test.",
        "error": "Error",
        "interrupted": "\nCommand interrupted.",
        "closed": "STARI closed.",
        "observation": "Observation",
        "evidence": "Evidence",
        "scan": "scan",
        "enter_command": "stari> ",
        "language_change_help": "To change the language, restart with start.bat --lang ru or start.bat --lang en.",
        "target_empty": "Target cannot be empty.",
        "scheme_unsupported": "Only http:// and https:// targets are supported.",
        "hostname_missing": "Target must contain a hostname.",
        "credentials_disallowed": "Credentials are not allowed in the target URL.",
        "query_fragment_disallowed": "Target must be an origin, without query or fragment.",
        "path_disallowed": "For this version, provide a domain/origin without a path.",
        "invalid_hostname": "Invalid hostname.",
        "project_not_initialized": "STARI project not initialized. Run: stari init --target example.com",
        "out_of_scope": "Out-of-scope URL blocked: {url}",
        "request_rate_value": "{value} request(s)/second",
        "response_cap_value": "{value} bytes",
    },
}


def current_language() -> str:
    return _LANGUAGE


def set_language(language: str) -> None:
    global _LANGUAGE
    normalized = language.strip().lower()
    if normalized not in SUPPORTED_LANGUAGES:
        raise ValueError("language must be 'ru' or 'en'.")
    _LANGUAGE = normalized


def tr(key: str, **kwargs: object) -> str:
    template = MESSAGES.get(_LANGUAGE, MESSAGES[_DEFAULT_LANGUAGE]).get(key, key).lower()
    return template.format(**kwargs) if kwargs else template


def preferences_path() -> Path:
    if os.name == "nt" and os.environ.get("APPDATA"):
        base = Path(os.environ["APPDATA"])
    elif os.environ.get("XDG_CONFIG_HOME"):
        base = Path(os.environ["XDG_CONFIG_HOME"])
    else:
        base = Path.home() / ".config"
    return base / "STARI" / "preferences.json"


def load_saved_language(path: Path | None = None) -> str | None:
    preference_file = path or preferences_path()
    try:
        data = json.loads(preference_file.read_text(encoding="utf-8"))
        language = str(data.get("language", "")).lower()
        return language if language in SUPPORTED_LANGUAGES else None
    except (OSError, json.JSONDecodeError, AttributeError):
        return None


def save_language(language: str, path: Path | None = None) -> None:
    normalized = language.strip().lower()
    if normalized not in SUPPORTED_LANGUAGES:
        raise ValueError("language must be 'ru' or 'en'.")
    preference_file = path or preferences_path()
    preference_file.parent.mkdir(parents=True, exist_ok=True)
    preference_file.write_text(
        json.dumps({"language": normalized}, indent=2), encoding="utf-8"
    )


def choose_language(
    requested: str | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    preference_file: Path | None = None,
) -> str:
    """Prompt for Russian/English and persist the selected UI language."""
    saved = load_saved_language(preference_file)
    if requested:
        selected = requested.strip().lower()
        if selected not in SUPPORTED_LANGUAGES:
            raise ValueError("use --lang ru or --lang en.")
    else:
        output_fn("\n" + MESSAGES["ru"]["language_title"].lower())
        output_fn("[1] русский")
        output_fn("[2] english")
        saved_label = ("русский" if saved == "ru" else "english") if saved else "русский"
        prompt = (
            f"choice [1/2] (enter — {saved_label}): "
            if saved == "en"
            else f"выбор [1/2] (enter — {saved_label}): "
        )
        try:
            choice = input_fn(prompt).strip().lower()
        except EOFError:
            choice = ""
        if choice in {"1", "ru", "русский", "russian"}:
            selected = "ru"
        elif choice in {"2", "en", "english"}:
            selected = "en"
        elif not choice:
            selected = saved or _DEFAULT_LANGUAGE
        else:
            if saved == "en":
                output_fn("unknown choice. keeping english.")
            else:
                output_fn("неизвестный выбор. включён русский язык.")
            selected = saved or _DEFAULT_LANGUAGE

    set_language(selected)
    try:
        save_language(selected, preference_file)
    except OSError:

        pass
    label = "русский" if selected == "ru" else "english"
    output_fn(tr("language_saved", language=label))
    return selected
