from __future__ import annotations

import hashlib
import re
import uuid
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from stari.core.config import ProjectConfig
from stari.core.models import Observation
from stari.core.scope import is_in_scope
from stari.engines.http_client import SafeHTTPClient
from stari.engines.robots import parse_robots
from stari.engines.sitemap import parse_sitemap



ADMIN_PATHS: tuple[str, ...] = (
    "admin", "admin/", "administrator/", "admin/login", "admin/login.php",
    "admin/index.php", "admin.php", "admin.html", "adminpanel/",
    "admin-panel/", "admin_area/", "adminarea/", "admincp/", "admin1/",
    "dashboard/", "dashboard.php", "dashboard/login", "controlpanel/",
    "cpanel/", "cp/", "webadmin/", "siteadmin/", "moderator/", "wp-admin/",
    "wp-login.php", "administrator/index.php", "joomla/administrator/",
    "bitrix/admin/", "phpmyadmin/", "pma/", "manager/", "cms/admin/",
    "panel/", "backend/", "manage/", "staff/", "secure/admin/", "adm/",
    "adm/index.php", "admin_login/", "admin-login/", "admin-console/",
    "console", "console/", "console/login", "console.php", "admin/console",
    "admin/dashboard", "adminpanel.php", "admin_area.php", "control/", "portal/admin",


    "login", "login/", "login.php", "login.html", "log-in/", "signin/",
    "sign-in/", "sign_in/", "auth/", "auth/login", "authenticate/",
    "account/", "account/login", "user/login", "users/login", "member/login",
    "members/login", "profile/login", "personal/", "cabinet/", "lk/",
    "sso/", "session/new",
)





_EXTRA_ADMIN_PATHS: tuple[str, ...] = (
    "admin-area/", "admin_area/", "adminarea/", "adminportal/", "admin-portal/",
    "admin-console/", "adminconsole/", "admincenter/", "admin-center/",
    "admincp/", "admin_cp/", "admincontrol/", "admin-control/",
    "adminlogin/", "admin_login.php", "admin-login.php", "adminsignin/",
    "admin-signin/", "admin_auth/", "admin-auth/", "adminauth/",
    "admin/index.html", "admin/default.aspx", "admin/default.asp",
    "admin/index.aspx", "admin/index.asp", "admin/index.html",
    "administrator/login/", "administrator/login.php", "administrator.php",
    "administrator.html", "administrator/index.html", "administrator/default.aspx",
    "adminpanel/login/", "admin-panel/login/", "admin/dashboard/",
    "admin/home/", "admin/main/", "adminarea/login/", "admin-area/login/",
    "console/", "console/login/", "console/index.php", "console/index.html",
    "console/default.aspx", "control/", "control/login/", "controlpanel/login/",
    "control-panel/login/", "control-center/", "controlcenter/",
    "manage/", "manage/login/", "management/", "management/login/",
    "manager/", "manager/login/", "manager/html/", "manager/index.html",
    "backoffice/", "back-office/", "backoffice/login/", "back-office/login/",
    "backend/", "backend/login/", "backend/admin/", "webadmin/", "webadmin/login/",
    "siteadmin/", "site-admin/", "site_admin/", "siteadmin/login/",
    "staff/", "staff/login/", "staff/portal/", "employee/", "employees/",
    "moderator/", "moderator/login/", "operator/", "operator/login/",
    "support/agent/", "support/admin/", "internal/", "internal/login/",
    "private/", "private/login/", "secure/", "secure/login/",
    "portal/", "portal/login/", "portal/admin/", "portal/signin/",
    "dashboard/", "dashboard/login/", "dashboard/index.php", "dashboard/index.html",
    "user/", "user/login/", "users/", "users/login/", "account/", "account/login/",
    "accounts/login/", "member/", "members/", "members/login/", "profile/login/",
    "auth/", "auth/login/", "auth/signin/", "authentication/", "authentication/login/",
    "login/index.php", "login/index.html", "login.aspx", "login.asp", "login.cfm",
    "signin.php", "signin.html", "sign-in.php", "sign-in.html", "sign_in.php",
    "logon/", "logon.php", "session/login/", "session/create/",
    "cms/", "cms/login/", "cms/admin/", "cms/index.php", "manage-system/",
    "system/", "system/login/", "system/admin/", "settings/", "settings/admin/",
    "web/administrator/", "webadmin.php", "admin.cgi", "admin.pl", "admin.py",
    "admin/index.cgi", "admin/index.pl", "admin/index.py",
    "wp-admin/", "wp-login.php", "wp-admin/network/", "wp-admin/options-general.php",
    "joomla/administrator/", "administrator/components/", "drupal/user/login/",
    "user/login/", "bitrix/admin/", "bitrix/admin/index.php", "magento/admin/",
    "backend.php", "adminer.php", "phpmyadmin/", "phpMyAdmin/", "pma/",
    "dbadmin/", "mysqladmin/", "pgadmin/", "phpPgAdmin/",
    "plesk/", "cpanel/", "whm/", "webmail/", "roundcube/",

    "admin-area/login/", "admin-console/login/", "adminportal/login/",
    "admin-center/login/", "admincontrol/login/", "admin/signin/",
    "admin/sign-in/", "admin/auth/login/", "admin/authenticate/",
    "login/admin/", "signin/admin/", "auth/admin/", "auth/sign-in/",
    "auth/signin/", "auth/authorize/", "account/signin/", "account/sign-in/",
    "account/access/", "accounts/sign-in/", "user/signin/", "users/signin/",
    "member/sign-in/", "members/sign-in/", "my-account/", "myaccount/",
    "my/account/", "my/login/", "client/", "client/login/", "client-area/",
    "customer/", "customer/login/", "customer-area/", "customer-portal/",
    "member-area/", "members-area/", "user-area/", "userpanel/",
    "user-panel/", "personal-account/", "personal-area/", "private-area/",
    "private-office/", "office/", "office/login/", "cabinet/", "cabinet/login/",
    "lk/", "lk/login/", "portal/access/", "portal/entry/", "portal/auth/",
    "staff-portal/", "employee-portal/", "operator-panel/", "control-room/",
    "management-console/", "system-admin/", "site-manager/", "web-manager/",
    "secure-login/", "secure-area/", "intranet/", "intranet/login/",
    "auth/login.php", "user/login.php", "account/login.php", "admin/signin.php",
    "admin/index.html", "admin/home.php", "admin/dashboard.php", "adminpanel/login.php",
    "controlpanel.php", "panel/login/", "panel/signin/", "panel/auth/",
    "backend/index.php", "backend/signin/", "backoffice/signin/", "manage/index.php",
)

ADMIN_PATHS = tuple(dict.fromkeys((*ADMIN_PATHS, *_EXTRA_ADMIN_PATHS)))

DEEP_ADMIN_PATHS: tuple[str, ...] = tuple(dict.fromkeys((
    *_EXTRA_ADMIN_PATHS,
    "admin1/", "admin2/", "admin3/", "admin4/", "admin5/", "admin6/",
    "admin7/", "admin8/", "admin9/", "admin10/", "administrator1/",
    "admin_old/", "old-admin/", "oldadmin/", "new-admin/", "newadmin/",
    "admin-new/", "admin_backup/", "admin-backup/", "backup/admin/",
    "admin-dev/", "dev/admin/", "test/admin/", "staging/admin/",
    "beta/admin/", "demo/admin/", "admin-dev.php", "admin-test/",
    "admin-old.php", "admin_bak/", "admin_bkp/", "admin-temp/",
    "admin_tmp/", "admin123/", "admin123.php", "admin2020/", "admin2021/",
    "admin2022/", "admin2023/", "admin2024/", "admin2025/", "admin2026/",
    "admin/log-in/", "admin/sign-in/", "admin/auth/", "admin/authenticate/",
    "admin/user/", "admin/users/", "admin/account/", "admin/settings/",
    "admin/config/", "admin/system/", "admin/manage/", "admin/console/",
    "admin/panel/", "admin/control/", "admin/home/", "admin/main/",
    "administrator/sign-in/", "administrator/auth/", "administrator/panel/",
    "administrator/console/", "administrator/dashboard/", "administrator/control/",
    "console/admin/", "console/dashboard/", "console/control/", "console/auth/",
    "manage/admin/", "manage/console/", "management/console/", "management/dashboard/",
    "control/admin/", "control/console/", "control/dashboard/", "controlpanel/",
    "control_panel/", "cpanel/", "cpanel/login/", "cpanel/index.php",
    "whm/login/", "plesk/login/", "webmail/login/", "roundcube/?_task=login",
    "admin/login.aspx", "admin/login.asp", "admin/login.cfm", "admin/login.cgi",
    "admin/login.pl", "admin/login.py", "administrator/login.aspx",
    "administrator/login.asp", "console/login.aspx", "console/login.php",
    "manage/login.php", "manager/login.php", "backend/login.php",
    "backoffice/login.php", "portal/admin/login/", "portal/administrator/",
    "staff/admin/", "staff/console/", "employee/login/", "employees/login/",
    "operator/console/", "operator/panel/", "secure/admin/", "secure/console/",
    "private/admin/", "private/console/", "internal/admin/", "internal/console/",
)))

_BASELINE_SAMPLES = 3
_MAX_PATHS = 320
_MAX_BODY_CHARS = 24_000
_MAX_DISCOVERED_LINKS = 25
_MAX_CRAWL_PAGES = 24
_MAX_JS_ASSETS = 16

_LOGIN_CUE = re.compile(
    r"\b(?:sign[\s-]*in|log[\s-]*in|login|logon|authenticate|user\s+name|"
    r"member\s+login|account\s+access|secure\s+access|enter\s+account|"
    r"my\s+account|account\s+portal|customer\s+portal|member\s+area|"
    r"continue\s+with|single\s+sign[\s-]*on|\bsso\b|"
    r"войти|вход|авторизац\w*|логин|личн\w*\s+кабинет|войти\s+в\s+аккаунт|"
    r"вход\s+в\s+систему|вход\s+в\s+панель|мой\s+кабинет|"
    r"личный\s+раздел|кабинет\s+пользователя|вход\s+для\s+клиентов)\b",
    re.IGNORECASE,
)
_ADMIN_CUE = re.compile(
    r"\b(?:admin(?:istration)?\s+(?:login|sign[\s-]?in|dashboard|panel|console|portal|area|interface|center|centre)|"
    r"administrator(?:\s+(?:login|dashboard|panel|console|portal))?|control\s+panel|"
    r"management\s+(?:console|portal|dashboard|interface)|site\s+administration|"
    r"back[\s-]?office|админ\w*|административн\w*\s+(?:панел\w*|вход\w*|консол\w*)|"
    r"панел\w*\s+управлен\w*|управлен\w*\s+сайт\w*|консоль\s+управлен\w*|"
    r"панель\s+администратора|кабинет\s+администратора)\b",
    re.IGNORECASE,
)
_IDENTITY_FIELD = re.compile(
    r"(?:^|[^a-zа-яё])(?:user(?:name)?|user[_-]?id|userid|uid|login|logon|"
    r"email|e-?mail|account|identifier|identity|credential|member|customer|client|"
    r"phone|telephone|mobile|tel|user_login|user_email|j_username|"
    r"номер|логин|почта|пользователь|"
    r"имя[\s_-]*пользователя|уч[её]тн\w*[\s_-]*запис\w*)(?:$|[^a-zа-яё])",
    re.IGNORECASE,
)
_PASSWORD_FIELD = re.compile(r"(?:pass(?:word|wd|code)?|pwd|secret|парол\w*)", re.IGNORECASE)
_AUTH_ACTION = re.compile(
    r"(?:login|logon|signin|sign-in|sign_in|authenticate|auth|sso|session|"
    r"oauth|account|cabinet|вход|войти|авторизац|кабинет)", re.IGNORECASE,
)
_ADMIN_CONTEXT = re.compile(
    r"(?:admin(?:istrator)?|administration|control[\s_-]*(?:panel|center|centre|room)|management[\s_-]*console|"
    r"back[\s_-]*office|staff[\s_-]*portal|operator[\s_-]*panel|"
    r"админ|администрац|панель[\s_-]*(?:управления|администратора)|"
    r"кабинет[\s_-]*администратора)", re.IGNORECASE,
)
_LOGIN_ROUTE = re.compile(
    r"(?:^|[/_.-])(?:login|logon|log-in|signin|sign-in|sign_in|auth|authenticate|"
    r"account|user|users|member|members|profile|personal|cabinet|lk|sso|session|"
    r"office|my-account|myaccount|client|customer|employee|intranet|portal|"
    r"вход|войти|авторизац\w*|личн\w*|кабинет|офис|профиль)(?:$|[/_.?&=-])",
    re.IGNORECASE,
)
_ADMIN_ROUTE = re.compile(
    r"(?:^|[/_.-])(?:admin(?:istrator)?|adminpanel|admin-panel|admin_area|adminarea|"
    r"admincp|adminportal|admin-console|wp-admin|wp-login|phpmyadmin|pma|bitrix|"
    r"dashboard|controlpanel|control-panel|control_center|control-center|controlcenter|webadmin|"
    r"siteadmin|backoffice|backend|management|manage|manager|console|moderator|"
    r"staff|operator|cpanel|whm|plesk|dbadmin|adm)(?:$|[/_.?&=-])",
    re.IGNORECASE,
)
_DYNAMIC_TOKEN = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{8}-[0-9a-f-]{20,}|[0-9a-f]{16,}(?:_\d+)?|\d{7,})(?![0-9a-f])", re.I
)
_SPACE = re.compile(r"\s+")
_CONTROL_PATH = re.compile(r"__stari_missing_[0-9a-f_]+", re.I)
_JS_PATH_LITERAL = re.compile(r"[\"'`](/[^\"'`\s<>]{1,180})[\"'`]")
_JS_ROUTE_HINT = re.compile(
    r"(?:admin|administrator|console|dashboard|manage|management|control|panel|"
    r"backoffice|backend|staff|operator|auth|login|signin|sign-in|account|user|"
    r"member|portal|secure|cabinet|админ|вход|авторизац)",
    re.IGNORECASE,
)


class _PageFeatureParser(HTMLParser):
    """Extract visible login cues, fields, controls and same-page links."""

    _CONTEXT_TAGS = {"title", "h1", "h2", "h3", "h4", "button", "label", "legend"}
    _HIDDEN_TAGS = {"script", "style", "noscript", "svg", "template"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_parts: list[str] = []
        self.context_parts: list[str] = []
        self.metadata_parts: list[str] = []
        self.inputs: list[dict[str, str]] = []
        self.form_actions: list[str] = []
        self.form_inputs: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.script_sources: list[str] = []
        self.interactive_control_count = 0
        self.submit_control_count = 0
        self._form_depth = 0
        self._hidden_depth = 0
        self._hidden_stack: list[str] = []
        self._context_stack: list[str] = []
        self._anchor_stack: list[dict[str, object]] = []
        self._nav_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script":
            src = attributes.get("src", "").strip()
            if src:
                self.script_sources.append(src)
        if tag in self._HIDDEN_TAGS:
            self._hidden_stack.append(tag)
            self._hidden_depth += 1
            return
        if self._hidden_depth:
            return

        if tag in {"nav", "header"}:
            self._nav_depth += 1

        for key in (
            "aria-label", "title", "placeholder", "data-testid", "name", "id",
            "class", "role", "autocomplete", "aria-describedby",
        ):
            value = attributes.get(key, "").strip()
            if value:
                self.metadata_parts.append(value)

        if tag == "a":
            self._anchor_stack.append({
                "href": attributes.get("href", ""),
                "text": [],
                "aria_label": attributes.get("aria-label", ""),
                "rel": attributes.get("rel", ""),
                "class": attributes.get("class", ""),
                "id": attributes.get("id", ""),
                "navigation": "yes" if self._nav_depth else "no",
            })
        elif tag == "form":
            self.form_actions.append(attributes.get("action", ""))
            self._form_depth += 1
            self.interactive_control_count += 1
        elif tag in {"button", "select", "textarea"} or attributes.get("role", "").lower() in {"button", "textbox", "combobox"}:
            self.interactive_control_count += 1
            if tag == "button" and attributes.get("type", "").lower() in {"submit", ""}:
                self.submit_control_count += 1
        elif tag in {"input"} and attributes.get("role", "").lower() in {"button", "submit"}:
            self.submit_control_count += 1
        elif tag == "input":
            self.interactive_control_count += 1
            field = {
                "type": attributes.get("type", "text").lower(),
                "name": attributes.get("name", "").lower(),
                "id": attributes.get("id", "").lower(),
                "placeholder": attributes.get("placeholder", "").lower(),
                "autocomplete": attributes.get("autocomplete", "").lower(),
                "aria_label": attributes.get("aria-label", "").lower(),
                "class": attributes.get("class", "").lower(),
                "data_testid": attributes.get("data-testid", "").lower(),
                "role": attributes.get("role", "").lower(),
                "required": "yes" if "required" in attributes else "no",
            }
            self.inputs.append(field)
            if self._form_depth > 0:
                self.form_inputs.append(field)
            if field["type"] in {"submit", "button"}:
                self.submit_control_count += 1
                if attributes.get("value"):
                    self.context_parts.append(attributes["value"])
        if tag in self._CONTEXT_TAGS:
            self._context_stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._form_depth > 0:
            self._form_depth -= 1
        if self._hidden_depth:
            if tag in self._hidden_stack:
                index = len(self._hidden_stack) - 1 - self._hidden_stack[::-1].index(tag)
                self._hidden_stack = self._hidden_stack[:index]
                self._hidden_depth = len(self._hidden_stack)
            return
        if tag == "a" and self._anchor_stack:
            anchor = self._anchor_stack.pop()
            self.links.append({
                "href": str(anchor.get("href", "")),
                "text": _SPACE.sub(" ", " ".join(anchor.get("text", []))).strip(),
                "aria_label": str(anchor.get("aria_label", "")),
                "rel": str(anchor.get("rel", "")),
                "class": str(anchor.get("class", "")),
                "id": str(anchor.get("id", "")),
                "navigation": str(anchor.get("navigation", "no")),
            })
        if tag in self._CONTEXT_TAGS and tag in self._context_stack:
            index = len(self._context_stack) - 1 - self._context_stack[::-1].index(tag)
            self._context_stack = self._context_stack[:index]
        if tag in {"nav", "header"} and self._nav_depth > 0:
            self._nav_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._hidden_depth:
            return
        value = data.strip()
        if not value:
            return
        self.visible_parts.append(value)
        if self._context_stack:
            self.context_parts.append(value)
        for anchor in self._anchor_stack:
            anchor["text"].append(value)


def _normalize_text(value: str) -> str:
    value = value.casefold()
    value = _CONTROL_PATH.sub(" <route> ", value)
    value = _DYNAMIC_TOKEN.sub(" <dynamic> ", value)
    value = _SPACE.sub(" ", value)
    return value.strip()


def _field_matches(field: dict[str, str], pattern: re.Pattern[str]) -> bool:
    return any(
        pattern.search(field.get(key, ""))
        for key in ("name", "id", "placeholder", "aria_label", "class", "data_testid", "role", "autocomplete")
    )


def _page_features(body: str) -> dict[str, object]:
    """Extract several independent signals from an HTML response.

    This is intentionally a static HTML inspection: scripts are not executed.
    It recognizes native forms, framework-style inputs, passwordless entry
    links and common localized labels, while ignoring footer-only login text.
    """
    parser = _PageFeatureParser()
    try:
        parser.feed(body[:_MAX_BODY_CHARS])
        parser.close()
    except Exception:
        pass

    visible_text = _normalize_text(" ".join(parser.visible_parts))
    context_text = _normalize_text(" ".join(parser.context_parts))
    metadata_text = _normalize_text(" ".join(parser.metadata_parts))
    anchor_text = _normalize_text(" ".join(str(item.get("text", "")) for item in parser.links))
    anchor_meta = _normalize_text(" ".join(
        " ".join((str(item.get("aria_label", "")), str(item.get("class", "")), str(item.get("id", ""))))
        for item in parser.links
    ))
    structural_text = " ".join(part for part in (context_text, metadata_text, anchor_text, anchor_meta) if part)

    password_fields = [
        field for field in parser.inputs
        if field.get("type") == "password" or _field_matches(field, _PASSWORD_FIELD)
    ]
    identity_fields = [
        field for field in parser.inputs
        if _field_matches(field, _IDENTITY_FIELD)
        or field.get("type") in {"email", "tel"}
        or field.get("autocomplete") in {"username", "email", "tel", "current-username"}
    ]
    form_password_fields = [
        field for field in parser.form_inputs
        if field.get("type") == "password" or _field_matches(field, _PASSWORD_FIELD)
    ]
    form_identity_fields = [
        field for field in parser.form_inputs
        if _field_matches(field, _IDENTITY_FIELD)
        or field.get("type") in {"email", "tel"}
        or field.get("autocomplete") in {"username", "email", "tel", "current-username"}
    ]

    login_cue = bool(_LOGIN_CUE.search(structural_text))
    admin_cue = bool(_ADMIN_CONTEXT.search(structural_text))
    auth_links = [
        item for item in parser.links
        if _AUTH_ACTION.search(" ".join((
            str(item.get("href", "")), str(item.get("text", "")),
            str(item.get("aria_label", "")), str(item.get("class", "")), str(item.get("id", "")),
        )))
    ]
    admin_links = [
        item for item in parser.links
        if _ADMIN_ROUTE.search(" ".join((
            str(item.get("href", "")), str(item.get("text", "")),
            str(item.get("aria_label", "")), str(item.get("class", "")), str(item.get("id", "")),
        )))
    ]
    form_actions_are_auth = any(_AUTH_ACTION.search(action) for action in parser.form_actions)
    submit_available = parser.submit_control_count >= 1 or any(
        str(item.get("role", "")).lower() in {"button", "menuitem"} for item in parser.inputs
    )
    has_form_or_action = bool(parser.form_actions) or form_actions_are_auth



    credential_pair = bool(password_fields) and bool(identity_fields)
    password_login = credential_pair and (
        bool(parser.form_actions) or parser.interactive_control_count >= 2 or login_cue
    )


    passwordless_login = (
        bool(identity_fields)
        and (login_cue or form_actions_are_auth or bool(auth_links))
        and (submit_available or has_form_or_action or bool(auth_links))
    )

    sso_cue = bool(re.search(r"(?:continue\s+with|single\s+sign[\s-]*on|\bsso\b|oauth)", structural_text, re.I))
    sso_entry = bool(auth_links) and sso_cue
    login_interface = password_login or passwordless_login or sso_entry
    login_form = bool(form_password_fields) and (bool(form_identity_fields) or login_cue)
    auth_route_links = len(auth_links)
    admin_route_links = len(admin_links)

    return {
        "visible_text": visible_text,
        "context_text": context_text,
        "metadata_text": metadata_text,
        "anchor_text": anchor_text,
        "password_fields": len(password_fields),
        "identity_fields": len(identity_fields),
        "form_password_fields": len(form_password_fields),
        "form_identity_fields": len(form_identity_fields),
        "login_cue": login_cue,
        "admin_cue": admin_cue,
        "login_form": login_form,
        "login_interface": login_interface,
        "passwordless_login": passwordless_login,
        "sso_entry": sso_entry,
        "auth_link_count": auth_route_links,
        "admin_link_count": admin_route_links,
        "form_count": len(parser.form_actions),
        "form_actions": parser.form_actions[:50],
        "interactive_control_count": parser.interactive_control_count,
        "submit_control_count": parser.submit_control_count,
        "links": parser.links[:100],
        "script_sources": parser.script_sources[:30],
    }


def _url_signature(url: str) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), (parsed.path or "/").rstrip("/") or "/"


def _comparison_text(features: dict[str, object], url: str) -> str:
    """Remove a reflected request path before comparing catch-all templates."""
    text = str(features.get("visible_text", ""))
    path = urlsplit(url).path
    if path and path != "/":
        text = re.sub(re.escape(path.casefold()), " <route> ", text, flags=re.I)
    return _SPACE.sub(" ", text).strip()


def _looks_like_soft_404(
    candidate_status: int,
    candidate_url: str,
    candidate_features: dict[str, object],
    baselines: list[dict[str, object]],
) -> bool:
    """Reject hard 404s and candidates matching a majority of control URLs.

    One matching control is not enough: some sites return a generic redirect
    or a shared shell for a single random path. Two independent controls must
    match the candidate before it is discarded as a soft 404.
    """
    if candidate_status in {404, 410}:
        return True
    if len(baselines) < 2:
        return False

    candidate_text = _comparison_text(candidate_features, candidate_url)
    matched = 0
    for baseline in baselines:
        baseline_url = str(baseline.get("request_url") or baseline.get("url", ""))
        baseline_features = baseline.get("features") or {}
        baseline_text = _comparison_text(baseline_features, baseline_url)
        same_status = candidate_status == int(baseline.get("status", 0))
        similar = False
        if candidate_text and baseline_text:
            if candidate_text == baseline_text:
                similar = True
            elif min(len(candidate_text), len(baseline_text)) >= 32:
                ratio = SequenceMatcher(
                    None, candidate_text[:_MAX_BODY_CHARS], baseline_text[:_MAX_BODY_CHARS], autojunk=True
                ).ratio()
                similar = ratio >= 0.92





        if similar and (same_status or candidate_status in {200, 203}):
            matched += 1
    return matched >= 2


def _baseline_is_stable(baselines: list[dict[str, object]]) -> bool:
    """Require all three negative controls to agree before strong claims."""
    if len(baselines) < _BASELINE_SAMPLES:
        return False
    statuses = {int(item.get("status", 0)) for item in baselines}
    if len(statuses) != 1:
        return False
    status = next(iter(statuses))
    if status in {404, 410}:
        return True
    if status not in {200, 203}:
        return False
    texts = []
    for item in baselines:
        url = str(item.get("request_url") or item.get("url", ""))
        texts.append(_comparison_text(item.get("features") or {}, url))
    if not all(texts):
        return False
    ratios = [
        SequenceMatcher(None, left[:_MAX_BODY_CHARS], right[:_MAX_BODY_CHARS], autojunk=True).ratio()
        for index, left in enumerate(texts)
        for right in texts[index + 1:]
    ]
    return bool(ratios) and min(ratios) >= 0.78



def _is_admin_like_path(path: str) -> bool:
    return bool(_ADMIN_ROUTE.search(path))


def _is_login_like_path(path: str) -> bool:
    return bool(_LOGIN_ROUTE.search(path))


def _same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    return (
        a.scheme.casefold(), (a.hostname or "").casefold(), a.port
    ) == (
        b.scheme.casefold(), (b.hostname or "").casefold(), b.port
    )


def _safe_candidate_path(path: str) -> str | None:
    path = path.strip()
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        return None
    if ".." in parsed.path.split("/") or "\\" in parsed.path or "\x00" in parsed.path:
        return None
    if len(parsed.path) > 512:
        return None
    return parsed.path


def _external_redirect_target(response: object) -> str | None:
    status = int(getattr(response, "status_code", 0))
    if status not in {301, 302, 303, 307, 308}:
        return None
    location = getattr(response, "headers", {}).get("location")
    if not location:
        return None
    return urljoin(str(getattr(response, "url", "")), str(location))


def _safe_redirect_display_url(url: str) -> str:
    """Drop query/fragment data because redirect URLs may carry auth tokens."""
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _is_external_redirect(client: SafeHTTPClient, response: object) -> bool:
    target = _external_redirect_target(response)
    return bool(target and not is_in_scope(target, client.config))


def _robots_admin_paths(text: str, base_url: str, config: ProjectConfig, *, limit: int = 30) -> list[dict[str, str]]:
    """Extract admin/login route hints from robots.txt; hints are never findings."""
    parsed = parse_robots(text)
    root = base_url.rstrip("/") + "/"
    found: dict[str, dict[str, str]] = {}

    for directive in ("disallow", "allow"):
        for raw_value in parsed.get(directive, []):
            value = raw_value.strip()
            if not value or not value.startswith("/") or "?" in value or "#" in value:
                continue
            stable = value.split("*", 1)[0].split("$", 1)[0].strip()
            if not stable or stable == "/":
                continue
            path = _safe_candidate_path(stable)
            if not path or not (_is_admin_like_path(path) or _is_login_like_path(path)):
                continue
            absolute = urljoin(root, path.lstrip("/"))
            if not is_in_scope(absolute, config):
                continue
            key = path.casefold().rstrip("/") or "/"
            found.setdefault(key, {"path": path, "source": f"robots.txt: {directive.title()}"})
            if len(found) >= limit:
                return list(found.values())
    return list(found.values())


async def _fetch_robots_admin_paths(client: SafeHTTPClient, base_url: str) -> tuple[list[dict[str, str]], int | None, str | None]:
    robots_url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
    try:
        response = await client.get(robots_url)
    except Exception as exc:
        return [], None, type(exc).__name__
    if response.status_code != 200 or not is_in_scope(response.url, client.config):
        return [], response.status_code, None
    return _robots_admin_paths(response.text, base_url, client.config), response.status_code, None


async def _discover_homepage_candidates(
    client: SafeHTTPClient, base_url: str
) -> tuple[list[dict[str, str]], dict[str, object] | None, str | None]:
    """Observe the homepage for actual login UI and links to login/admin routes."""
    try:
        response = await client.get(base_url)
    except Exception as exc:
        return [], None, type(exc).__name__
    if response.status_code != 200 or not is_in_scope(response.url, client.config):
        return [], None, None
    content_type = str(response.headers.get("content-type", "")).lower()
    if "html" not in content_type and not response.text.lstrip().lower().startswith(("<!doctype html", "<html")):
        return [], None, None

    features = _page_features(response.text)
    candidates: dict[str, dict[str, str]] = {}
    external_login_links: dict[str, dict[str, str]] = {}
    related_subdomain_links: dict[str, dict[str, str]] = {}
    root = base_url.rstrip("/") + "/"
    base_host = (urlsplit(base_url).hostname or "").casefold().rstrip(".")
    for link in features.get("links", []):
        href = str(link.get("href", "")).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        absolute = urljoin(response.url, href)
        parsed = urlsplit(absolute)
        host = (parsed.hostname or "").casefold().rstrip(".")
        path = _safe_candidate_path(parsed.path) or "/"
        label = str(link.get("text", "")).strip()
        login_like = (
            _is_admin_like_path(path)
            or _is_login_like_path(path)
            or _is_login_like_path(label)
            or _is_admin_like_path(label)
        )



        if host and base_host and host.endswith("." + base_host) and not is_in_scope(absolute, client.config):
            related_subdomain_links.setdefault(host, {
                "host": host,
                "path": parsed.path or "/",
                "label": label[:80],
                "url": _safe_redirect_display_url(absolute),
                "status": "OUT_OF_SCOPE_NOT_REQUESTED",
            })

        if not is_in_scope(absolute, client.config) or not _same_origin(base_url, absolute):
            if login_like:
                external_login_links.setdefault(_safe_redirect_display_url(absolute), {
                    "destination": _safe_redirect_display_url(absolute),
                    "host": host,
                    "label": label[:80],
                    "status": "OUT_OF_SCOPE_NOT_REQUESTED",
                })
            continue

        if not path or path == "/" or not login_like:
            continue
        key = path.casefold().rstrip("/") or "/"
        candidates.setdefault(key, {
            "path": path,
            "source": f"homepage-link: {label[:60]}" if label else "homepage-link",
        })
        if len(candidates) >= _MAX_DISCOVERED_LINKS:
            break

    features["external_login_links"] = list(external_login_links.values())[:20]
    features["related_subdomain_links"] = list(related_subdomain_links.values())[:20]
    return list(candidates.values()), features, None


async def _discover_sitemap_candidates(client: SafeHTTPClient, base_url: str) -> tuple[list[dict[str, str]], int | None, str | None]:
    sitemap_url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
    try:
        response = await client.get(sitemap_url)
    except Exception as exc:
        return [], None, type(exc).__name__
    if response.status_code != 200 or not is_in_scope(response.url, client.config) or response.truncated:
        return [], response.status_code, None
    try:
        locations, _ignored = parse_sitemap(response.text, base_url, client.config)
    except Exception:
        return [], response.status_code, None

    found: dict[str, dict[str, str]] = {}
    for location in locations:
        parsed = urlsplit(location)
        if not _same_origin(base_url, location):
            continue
        path = _safe_candidate_path(parsed.path)
        if not path or not (_is_admin_like_path(path) or _is_login_like_path(path)):
            continue
        key = path.casefold().rstrip("/") or "/"
        found.setdefault(key, {"path": path, "source": "sitemap.xml"})
        if len(found) >= _MAX_DISCOVERED_LINKS:
            break
    return list(found.values()), response.status_code, None


def _link_is_interesting(href: str, label: str = "", metadata: str = "") -> bool:
    combined = " ".join((href, label, metadata))
    account_hint = re.compile(
        r"(?:my[\s_-]*account|account[\s_-]*(?:area|portal)|customer[\s_-]*portal|"
        r"member[\s_-]*area|personal[\s_-]*area|private[\s_-]*office|"
        r"личн\w*[\s_-]*кабинет|мой[\s_-]*кабинет|кабинет[\s_-]*пользователя|"
        r"войти|вход|sign[\s_-]*in|log[\s_-]*in)", re.IGNORECASE,
    )
    return bool(_ADMIN_ROUTE.search(combined) or _LOGIN_ROUTE.search(combined) or _LOGIN_CUE.search(combined) or account_hint.search(combined))


def _candidate_from_url(url: str, base_url: str, config: ProjectConfig, source: str) -> dict[str, str] | None:
    if not is_in_scope(url, config) or not _same_origin(base_url, url):
        return None
    parsed = urlsplit(url)
    path = _safe_candidate_path(parsed.path or "/")
    if not path or path == "/":
        return None


    suffix = path.rsplit("/", 1)[-1].lower()
    if re.search(r"\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$", suffix) and not _link_is_interesting(path):
        return None
    return {"path": path, "source": source}


async def _discover_crawled_candidates(
    client: SafeHTTPClient,
    base_url: str,
    homepage_features: dict[str, object] | None,
    *,
    page_limit: int = _MAX_CRAWL_PAGES,
) -> tuple[list[dict[str, str]], dict[str, int], list[str], list[str]]:
    """Crawl a small same-origin navigation surface and inspect linked JS routes.

    This is discovery, not a general-purpose spider: it prioritizes navigation,
    account and management links, remains in the exact configured scope, and
    uses GET only. JavaScript is parsed as text; it is never executed.
    """
    root = base_url.rstrip("/") + "/"
    queue: list[tuple[str, str, int]] = []
    candidates: dict[str, dict[str, str]] = {}
    script_urls: dict[str, str] = {}
    visited: set[str] = set()
    page_count = 0
    script_count = 0
    out_of_scope_links: list[str] = []

    def enqueue_links(features: dict[str, object], source_url: str, depth: int) -> None:
        for link in features.get("links", []) or []:
            href = str(link.get("href", "")).strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urljoin(source_url, href)
            parsed = urlsplit(absolute)
            if not parsed.hostname:
                continue
            if not is_in_scope(absolute, client.config) or not _same_origin(base_url, absolute):
                if _link_is_interesting(href, str(link.get("text", "")), str(link.get("aria_label", ""))):
                    safe_url = _safe_redirect_display_url(absolute)
                    if safe_url not in out_of_scope_links and len(out_of_scope_links) < 40:
                        out_of_scope_links.append(safe_url)
                continue

            path = _safe_candidate_path(parsed.path or "/")
            if not path or path == "/":
                continue
            label = " ".join((str(link.get("text", "")), str(link.get("aria_label", "")))).strip()
            metadata = " ".join((str(link.get("rel", "")), str(link.get("class", "")), str(link.get("id", ""))))
            interesting = _link_is_interesting(path, label, metadata)
            if interesting:
                item = _candidate_from_url(absolute, base_url, client.config, f"site-crawl-link: {label[:60]}" if label else "site-crawl-link")
                if item:
                    key = item["path"].casefold().rstrip("/") or "/"
                    candidates.setdefault(key, item)



            nav_link = str(link.get("navigation", "no")) == "yes"
            if depth < 2 and (interesting or nav_link):
                normalized = urljoin(root, path.lstrip("/"))
                if normalized not in visited and len(queue) < page_limit * 3:
                    queue.append((normalized, label or path, depth + 1))

        for raw_action in features.get("form_actions", []) or []:
            action = str(raw_action).strip()
            if not action:
                continue
            absolute = urljoin(source_url, action)
            if not is_in_scope(absolute, client.config) or not _same_origin(base_url, absolute):
                continue
            item = _candidate_from_url(absolute, base_url, client.config, "linked-form-action")
            if item and _link_is_interesting(item["path"], action):
                key = item["path"].casefold().rstrip("/") or "/"
                candidates.setdefault(key, item)

        for raw_script in features.get("script_sources", []) or []:
            absolute = urljoin(source_url, str(raw_script))
            parsed = urlsplit(absolute)
            if (
                is_in_scope(absolute, client.config)
                and _same_origin(base_url, absolute)
                and parsed.path.lower().endswith(".js")
                and len(script_urls) < _MAX_JS_ASSETS * 3
            ):
                script_urls.setdefault(absolute, source_url)

    if homepage_features:
        enqueue_links(homepage_features, base_url, 0)



    crawl_responses: dict[str, object] = {}
    while queue and page_count < max(0, min(page_limit, 40)):
        queue.sort(key=lambda item: (not _link_is_interesting(item[0], item[1]), item[2]))
        page_url, label, depth = queue.pop(0)
        key = page_url.casefold()
        if key in visited:
            continue
        visited.add(key)
        try:
            response = await client.get(page_url)
        except Exception:
            continue
        crawl_responses[page_url] = response
        page_count += 1
        if _is_external_redirect(client, response):
            continue
        if not (200 <= response.status_code < 300):
            continue
        content_type = str(response.headers.get("content-type", "")).lower()
        if "html" not in content_type and not response.text.lstrip().lower().startswith(("<!doctype html", "<html")):
            continue
        features = _page_features(response.text)
        current_path = urlsplit(response.url).path or "/"
        if features.get("login_interface") or features.get("admin_cue") or _is_admin_like_path(current_path) or _is_login_like_path(current_path):
            item = _candidate_from_url(response.url, base_url, client.config, f"site-crawl-page: {label[:60]}")
            if item:
                route_key = item["path"].casefold().rstrip("/") or "/"
                candidates.setdefault(route_key, item)
        enqueue_links(features, response.url, depth)



    for script_url, source_page in list(script_urls.items())[:_MAX_JS_ASSETS]:
        try:
            response = await client.get(script_url)
        except Exception:
            continue
        script_count += 1
        if response.status_code != 200 or response.truncated or _is_external_redirect(client, response):
            continue
        text = response.text[:_MAX_BODY_CHARS * 8]
        for match in _JS_PATH_LITERAL.finditer(text):
            raw_path = match.group(1)
            if not _JS_ROUTE_HINT.search(raw_path):
                continue
            item = _candidate_from_url(urljoin(root, raw_path.lstrip("/")), base_url, client.config, "javascript-route")
            if not item:
                continue
            route_key = item["path"].casefold().rstrip("/") or "/"
            candidates.setdefault(route_key, item)
            if len(candidates) >= _MAX_DISCOVERED_LINKS * 4:
                break

    stats = {"pages_crawled": page_count, "javascript_assets_inspected": script_count}
    return list(candidates.values())[:_MAX_DISCOVERED_LINKS * 4], stats, out_of_scope_links, list(script_urls)[:_MAX_JS_ASSETS]


async def check_admin_panels(
    client: SafeHTTPClient,
    base_url: str,
    *,
    paths: tuple[str, ...] = ADMIN_PATHS,
    deep: bool = False,
    custom_paths: tuple[str, ...] = (),
    crawl_pages: int = _MAX_CRAWL_PAGES,
    max_paths: int | None = None,
) -> list[Observation]:
    """Find verified admin interfaces and separately report actual login pages.

    Discovery combines robots.txt hints, sitemap URLs, navigation links, a
    bounded same-origin crawl, JavaScript route literals and an independently
    maintained path catalogue. A route is never called a panel merely because
    it was guessed or returned HTTP 200. Login forms and administrative UI are
    classified separately. Control URLs filter catch-all responses without
    making an unstable control sample suppress every otherwise strong result.
    """
    root = base_url.rstrip("/") + "/"
    robots_paths, robots_status, robots_error = await _fetch_robots_admin_paths(client, base_url)
    homepage_paths, homepage_features, homepage_error = await _discover_homepage_candidates(client, base_url)
    sitemap_paths, sitemap_status, sitemap_error = await _discover_sitemap_candidates(client, base_url)
    crawl_paths, crawl_stats, crawl_out_of_scope, js_assets = await _discover_crawled_candidates(
        client, base_url, homepage_features, page_limit=crawl_pages,
    )
    external_login_links = (homepage_features or {}).get("external_login_links", [])
    related_subdomain_links = (homepage_features or {}).get("related_subdomain_links", [])

    ordered_paths: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for group in (robots_paths, homepage_paths, sitemap_paths, crawl_paths):
        for item in group:
            path = _safe_candidate_path(str(item.get("path", "")))
            if not path:
                continue
            key = path.casefold().rstrip("/") or "/"
            if key not in seen_paths:
                ordered_paths.append({"path": path, "source": item.get("source", "discovered")})
                seen_paths.add(key)
    selected_paths = list(paths)
    if deep:
        selected_paths.extend(DEEP_ADMIN_PATHS)
    selected_paths.extend(custom_paths)
    requested_limit = max_paths if max_paths is not None else (550 if deep else _MAX_PATHS)
    path_limit = max(1, min(int(requested_limit), 600))
    for raw_path in selected_paths:
        path = _safe_candidate_path("/" + raw_path.strip().lstrip("/"))
        if not path or path == "/":
            continue
        key = path.casefold().rstrip("/") or "/"
        if key not in seen_paths:
            ordered_paths.append({"path": path, "source": "built-in"})
            seen_paths.add(key)
        if len(ordered_paths) >= path_limit:
            break
    ordered_paths = ordered_paths[:path_limit]

    baselines: list[dict[str, object]] = []
    baseline_errors: list[str] = []
    for index in range(_BASELINE_SAMPLES):
        baseline_url = urljoin(root, f"__stari_missing_{uuid.uuid4().hex}_{index}")
        try:
            response = await client.get(baseline_url)
            baselines.append({
                "status": response.status_code,
                "url": response.url,
                "request_url": baseline_url,
                "features": _page_features(response.text),
                "content_type": response.headers.get("content-type", ""),
            })
        except Exception as exc:
            baseline_errors.append(type(exc).__name__)




    baseline_available = len(baselines) >= 2
    baseline_stable = _baseline_is_stable(baselines)


    verified_admin: list[dict[str, object]] = []
    login_pages: list[dict[str, object]] = []
    checked = 0
    soft_404_count = 0
    restricted_count = 0
    non_html_count = 0
    weak_signal_count = 0
    ordinary_login_count = 0
    errors: list[str] = []
    external_redirects = 0
    external_redirect_records: list[dict[str, object]] = []
    restricted_records: list[dict[str, object]] = []
    baseline_unreliable_rejections = 0




    page_items: list[dict[str, object]] = []
    if homepage_features is not None and (
        bool(homepage_features.get("login_interface"))
        or (bool(homepage_features.get("admin_cue")) and int(homepage_features.get("interactive_control_count", 0)) >= 2)
    ):
        page_items.append({"path": "/", "source": "homepage", "features": homepage_features, "response": None, "request_url": base_url})

    for path_item in ordered_paths:
        path = str(path_item["path"])
        url = urljoin(root, path.lstrip("/"))
        checked += 1
        try:
            response = await client.get(url)
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}")
            continue
        if _is_external_redirect(client, response):
            external_redirects += 1
            redirect_target = _external_redirect_target(response)
            if redirect_target:
                external_redirect_records.append({
                    "path": path,
                    "source": path_item.get("source", "built-in"),
                    "http_status": response.status_code,
                    "destination": _safe_redirect_display_url(redirect_target),
                    "classification": "EXTERNAL_REDIRECT_NOT_INSPECTED",
                    "evidence": "The in-scope route returned an external redirect; STARI did not request the destination.",
                })
            continue
        if response.status_code in {401, 403}:
            restricted_count += 1
            restricted_records.append({
                "path": path,
                "source": path_item.get("source", "built-in"),
                "http_status": response.status_code,
                "final_url": _safe_redirect_display_url(response.url),
                "www_authenticate": str(response.headers.get("www-authenticate", ""))[:160],
                "classification": "RESTRICTED_ROUTE_NOT_CONFIRMED_AS_ADMIN",
            })
            continue
        if response.status_code not in {200, 203}:
            continue
        content_type = str(response.headers.get("content-type", "")).lower()
        media_type = content_type.split(";", 1)[0].strip()
        body_prefix = response.text.lstrip()[:256].lower()
        looks_html = media_type in {"text/html", "application/xhtml+xml"} or (
            not media_type and ("<html" in body_prefix or "<!doctype html" in body_prefix)
        )
        if not looks_html:
            non_html_count += 1
            continue
        features = _page_features(response.text)
        page_items.append({"path": path, "source": path_item.get("source", "built-in"), "features": features, "response": response, "request_url": url})

    for page_item in page_items:
        response = page_item.get("response")
        path = str(page_item.get("path", "/"))
        request_url = str(page_item.get("request_url", base_url))
        features = page_item.get("features") or {}
        if response is not None:
            if _looks_like_soft_404(response.status_code, response.url, features, baselines):
                soft_404_count += 1
                continue
            final_url = response.url
            http_status = response.status_code
            content_type = str(response.headers.get("content-type", ""))
        else:
            if _looks_like_soft_404(200, request_url, features, baselines):
                soft_404_count += 1
                continue
            final_url = request_url
            http_status = 200
            content_type = "text/html"

        source = str(page_item.get("source", "built-in"))
        final_path = urlsplit(final_url).path or "/"
        admin_path = _is_admin_like_path(path) or _is_admin_like_path(final_path)
        source_admin_hint = bool(_ADMIN_CONTEXT.search(source) or _ADMIN_ROUTE.search(source))
        admin_cue = bool(features.get("admin_cue"))
        login_interface = bool(features.get("login_interface"))
        login_form = bool(features.get("login_form"))
        auth_link_count = int(features.get("auth_link_count", 0))
        admin_link_count = int(features.get("admin_link_count", 0))
        password_fields = int(features.get("password_fields", 0))
        identity_fields = int(features.get("identity_fields", 0))
        interactive_controls = int(features.get("interactive_control_count", 0))
        route_login_hint = _is_login_like_path(path) or _is_login_like_path(final_path)




        admin_login = login_interface and (admin_path or admin_cue or source_admin_hint)
        admin_dashboard = (
            admin_cue
            and (admin_path or source_admin_hint or admin_link_count >= 1)
            and interactive_controls >= 2
        )
        actual_login_page = login_interface or (
            bool(features.get("login_cue")) and auth_link_count >= 1
        )

        if not actual_login_page and not admin_dashboard:
            has_relevant_signal = (
                admin_path or route_login_hint or admin_cue
                or bool(features.get("login_cue"))
                or password_fields > 0 or identity_fields > 0
                or auth_link_count > 0 or admin_link_count > 0
            )
            if has_relevant_signal:
                weak_signal_count += 1
            continue

        reasons: list[str] = []
        if password_fields:
            reasons.append(f"password controls: {password_fields}")
        if identity_fields:
            reasons.append(f"identity controls: {identity_fields}")
        if login_form:
            reasons.append("credential controls are contained in an HTML form")
        elif login_interface:
            reasons.append("credential or passwordless sign-in controls are present in HTML")
        if bool(features.get("login_cue")):
            reasons.append("sign-in wording appears in page context or accessible control labels")
        if auth_link_count:
            reasons.append(f"authentication links: {auth_link_count}")
        if admin_cue:
            reasons.append("administrative wording appears in page context")
        if admin_link_count:
            reasons.append(f"administrative navigation links: {admin_link_count}")
        if admin_path:
            reasons.append("requested or final route has an administrative path marker")
        if not baseline_stable:
            reasons.append("negative-control baseline unavailable or inconsistent; shown as observed, not verified")

        is_admin_interface = admin_login or admin_dashboard
        if admin_dashboard and not login_interface:
            classification = "VERIFIED_ADMIN_INTERFACE"
        elif is_admin_interface:
            classification = "VERIFIED_ADMIN_LOGIN"
        elif actual_login_page:
            classification = "LOGIN_PAGE"
        else:
            classification = "ADMIN_UI_OBSERVED_UNVERIFIED"

        record = {
            "path": path,
            "source": source,
            "requested_url": request_url,
            "final_url": final_url,
            "http_status": http_status,
            "content_type": content_type,
            "admin_like_path": admin_path,
            "login_form": login_form,
            "login_interface": login_interface,
            "admin_context_marker": admin_cue,
            "password_field_count": password_fields,
            "identity_field_count": identity_fields,
            "auth_link_count": auth_link_count,
            "admin_link_count": admin_link_count,
            "interactive_control_count": interactive_controls,
            "content_fingerprint": hashlib.sha256(
                "|".join((
                    str(features.get("visible_text", ""))[:5000],
                    str(features.get("context_text", ""))[:2000],
                    str(features.get("metadata_text", ""))[:2000],
                    str(password_fields), str(identity_fields),
                    str(features.get("form_count", 0)),
                )).encode("utf-8", errors="replace")
            ).hexdigest()[:16],
            "classification": classification,
            "confidence": "HIGH" if baseline_stable and (login_form or (login_interface and (admin_cue or admin_path))) else (
                "MEDIUM" if baseline_available else "LOW"
            ),
            "verification": "DISTINCT_FROM_TWO_OR_MORE_CONTROL_URLS" if baseline_stable else "OBSERVED_WITHOUT_STABLE_NEGATIVE_CONTROL",
            "evidence_reasons": reasons,
        }

        if not baseline_stable:


            record["classification"] = "OBSERVED_ADMIN_LOGIN_UNVERIFIED" if admin_login else (
                "OBSERVED_LOGIN_UNVERIFIED" if actual_login_page else "OBSERVED_ADMIN_UI_UNVERIFIED"
            )
            login_pages.append(record)
            ordinary_login_count += 1
            baseline_unreliable_rejections += 1
        elif is_admin_interface:
            verified_admin.append(record)
        elif actual_login_page:
            login_pages.append(record)
            ordinary_login_count += 1
        else:


            weak_signal_count += 1




    def _dedupe(records: list[dict[str, object]]) -> list[dict[str, object]]:
        seen_urls: dict[str, dict[str, object]] = {}
        result: list[dict[str, object]] = []
        for item in records:
            key = str(item.get("final_url", "")).casefold()
            if key and key in seen_urls:
                primary = seen_urls[key]
                aliases = primary.setdefault("also_observed_at", [])
                aliases.append({"path": item.get("path"), "source": item.get("source")})
                continue
            item.setdefault("also_observed_at", [])
            if key:
                seen_urls[key] = item
            result.append(item)
        return result

    verified_admin = _dedupe(verified_admin)
    login_pages = _dedupe(login_pages)
    verified_count = len(verified_admin)
    login_page_count = len(login_pages)
    if verified_count:
        status = "CONFIRMED"
        title = "Verified administrative interfaces found"
    elif login_page_count:
        status = "LOGIN_PAGES_FOUND"
        title = "Login pages found; admin role not confirmed"
    else:
        status = "NO_VERIFIED_ADMIN_PANEL"
        title = "No admin interface or login page found"

    details = (
        f"Checked {checked} candidate paths; verified admin interfaces: {verified_count}; "
        f"login pages: {login_page_count}. "
        f"robots.txt hints: {len(robots_paths)} (HTTP {robots_status if robots_status is not None else 'unavailable'}); "
        f"homepage links: {len(homepage_paths)}; sitemap routes: {len(sitemap_paths)}; "
        f"crawled routes: {len(crawl_paths)}; pages crawled: {crawl_stats['pages_crawled']}; "
        f"JS assets inspected: {crawl_stats['javascript_assets_inspected']}. "
        f"Soft-404/catch-all filtered: {soft_404_count}; 401/403 not counted: {restricted_count}; "
        f"non-HTML ignored: {non_html_count}; ambiguous signals ignored: {weak_signal_count}; "
        f"external redirects excluded: {external_redirects}."
    )
    if not baseline_stable:
        details += " Control URL samples were missing or inconsistent; low-confidence routes were not upgraded to high confidence."
    if robots_error:
        details += f" robots.txt request failed ({robots_error})."
    if homepage_error:
        details += f" Homepage discovery failed ({homepage_error})."
    if sitemap_error:
        details += f" Sitemap discovery failed ({sitemap_error})."
    if errors:
        details += f" {len(errors)} candidate requests failed."

    return [Observation(
        "ADMIN_PANEL_DISCOVERY",
        title,
        "INFO",
        status,
        base_url,
        details,
        {
            "checked_paths": checked,
            "robots_http_status": robots_status,
            "robots_request_error": robots_error,
            "robots_admin_path_hint_count": len(robots_paths),
            "homepage_candidate_count": len(homepage_paths),
            "homepage_request_error": homepage_error,
            "sitemap_http_status": sitemap_status,
            "sitemap_candidate_count": len(sitemap_paths),
            "sitemap_request_error": sitemap_error,
            "crawl_candidate_count": len(crawl_paths),
            "pages_crawled": crawl_stats["pages_crawled"],
            "javascript_assets_inspected": crawl_stats["javascript_assets_inspected"],
            "javascript_assets_seen": js_assets,
            "out_of_scope_crawl_links": crawl_out_of_scope[:20],
            "deep_wordlist_enabled": bool(deep),
            "configured_path_limit": path_limit,
            "built_in_path_count": len(selected_paths),
            "custom_wordlist_path_count": len(custom_paths),
            "discovered_path_count": len(robots_paths) + len(homepage_paths) + len(sitemap_paths) + len(crawl_paths),
            "candidate_count": verified_count,
            "verified_count": verified_count,
            "login_page_count": login_page_count,
            "restricted_unverified_count": restricted_count,
            "restricted_routes": restricted_records[:30],
            "non_html_ignored_count": non_html_count,
            "weak_signal_ignored_count": weak_signal_count,
            "related_login_page_count": ordinary_login_count,
            "unclassified_route_count": weak_signal_count,
            "soft_404_filtered": soft_404_count,
            "out_of_scope_redirects_excluded": external_redirects,
            "external_redirects": external_redirect_records[:20],
            "external_login_links": external_login_links[:20],
            "related_subdomain_links": related_subdomain_links[:20],
            "baseline_samples": len(baselines),
            "baseline_available": baseline_available,
            "baseline_stable": baseline_stable,
            "baseline_errors": baseline_errors[:10],
            "baseline_unreliable_rejections": baseline_unreliable_rejections,
            "baseline_stable_control_count": 2 if baseline_stable else 0,
            "candidates": verified_admin,
            "login_pages": login_pages,
            "request_errors": errors[:20],
            "method": "GET",
            "authentication_attempts": 0,
            "javascript_executed": False,
        },
    )]
