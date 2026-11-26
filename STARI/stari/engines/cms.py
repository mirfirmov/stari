from __future__ import annotations

import re
from html.parser import HTMLParser

from stari.core.models import Observation
from stari.engines.http_client import SafeHTTPClient


class _FingerprintParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: list[tuple[str, str]] = []
        self.resources: list[str] = []
        self.html_attributes: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        lowered_tag = tag.lower()
        if lowered_tag == "html":
            self.html_attributes.update(values)
        if lowered_tag == "meta":
            name = (values.get("name") or values.get("property") or "").lower()
            content = values.get("content", "")
            if name and content:
                self.meta.append((name, content[:300]))
        if lowered_tag in {"script", "link", "img"}:
            resource = values.get("src") or values.get("href")
            if resource:
                self.resources.append(resource[:500])


def _confidence(score: int) -> tuple[int, str]:
    value = max(0, min(100, score))
    if value >= 80:
        level = "HIGH"
    elif value >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"
    return value, level


async def check_cms(client: SafeHTTPClient, base_url: str) -> list[Observation]:
    """Fingerprint CMS and common web technologies using weighted public signals."""
    try:
        response = await client.get(base_url.rstrip("/") + "/")
    except Exception as exc:
        return [Observation(
            "CMS_DETECTION_ERROR", "CMS detection failed", "INFO", "ERROR", base_url,
            f"{type(exc).__name__}: {str(exc)[:300]}", {"error_type": type(exc).__name__},
        )]

    document = response.text.lower()
    headers = response.headers
    cookies = "\n".join(
        value for name, value in (response.header_items or list(headers.items()))
        if name.lower() == "set-cookie"
    ).lower()
    parser = _FingerprintParser()
    try:
        parser.feed(response.text)
    except Exception:
        pass
    meta_text = "\n".join(f"{name}={value}" for name, value in parser.meta).lower()
    resource_text = "\n".join(parser.resources).lower()
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
    combined = "\n".join((document, meta_text, resource_text, cookies, header_text))



    signatures: dict[str, tuple[tuple[str, int], ...]] = {
        "WordPress": (
            ("/wp-content/", 45), ("/wp-includes/", 45), ("wp-json", 35),
            ("wordpress", 20), ("wp-emoji-release", 25), ("wp-embed.min.js", 30),
            ("wordpress", 35),
        ),
        "Joomla": (
            ("joomla!", 65), ("/media/system/js/", 45), ("com_content", 40),
            ("joomla_", 40), ("option=com_", 25),
        ),
        "Drupal": (
            ("drupal.settings", 65), ("drupal.js", 55), ("/sites/default/files/", 45),
            ("/core/misc/drupal.js", 60), ("drupal", 20),
        ),
        "1C-Bitrix": (
            ("/bitrix/", 55), ("bitrix_sessid", 75), ("bx.message", 55),
            ("1c-bitrix", 65),
        ),
        "Magento": (
            ("mage/cookies", 60), ("/static/frontend/", 55), ("magento_", 45),
            ("x-magento", 65), ("mage/validation", 50),
        ),
        "OpenCart": (
            ("catalog/view/theme/", 55), ("index.php?route=", 60),
            ("opencart", 65), ("route=common/home", 50),
        ),
        "Shopify": (
            ("cdn.shopify.com", 65), ("myshopify.com", 80),
            ("shopify.theme", 55), ("shopify-features", 40),
        ),
        "Wix": (
            ("wixstatic.com", 70), ("_wix_browser_sess", 80),
            ("wix.com/", 35), ("wixsite.com", 55),
        ),
        "Squarespace": (
            ("static.squarespace.com", 70), ("squarespace-cdn.com", 70),
            ("squarespace", 25),
        ),
        "TYPO3": (
            ("typo3conf/", 60), ("typo3temp/", 60), ("typo3", 25),
        ),
        "Ghost": (
            ("ghost/api/", 65), ("content/images/ghost", 65),
            ("ghost.org", 45),
        ),
        "PrestaShop": (
            ("prestashop", 45), ("prestashop_version", 80),
            ("/modules/ps_", 55), ("content=prestashop", 75),
        ),
        "Craft CMS": (
            ("craftcms", 75), ("/cpresources/", 55), ("craft\\csrf", 45),
        ),
        "October CMS": (
            ("october.cms", 70), ("/modules/system/", 30),
            ("october_session", 75),
        ),
        "Umbraco": (
            ("umbraco", 40), ("/umbraco/", 70), ("umbracoforms", 65),
        ),
        "Contentful": (
            ("ctfassets.net", 70), ("contentful", 35),
        ),
        "Strapi": (
            ("strapi", 45), ("/uploads/", 10), ("x-powered-by: strapi", 80),
        ),
    }

    generator_values = [value for name, value in parser.meta if name == "generator"]
    detected: list[dict[str, object]] = []
    for cms, markers in signatures.items():
        matched: list[dict[str, object]] = []
        score = 0
        seen_markers: set[str] = set()
        for marker, weight in markers:
            if marker in combined and marker not in seen_markers:
                seen_markers.add(marker)
                score += weight
                matched.append({"signal": marker, "weight": weight})
        for generator in generator_values:
            if cms.lower() in generator.lower():
                score += 90
                matched.append({"signal": f"meta generator: {generator[:120]}", "weight": 90})
        if matched:
            confidence, level = _confidence(score)


            strong = any(int(item["weight"]) >= 40 for item in matched)
            if strong or len(matched) >= 2:
                detected.append({
                    "name": cms,
                    "score": min(score, 100),
                    "confidence": confidence,
                    "confidence_level": level,
                    "signals": [str(item["signal"]) for item in matched[:10]],
                })

    if generator_values:
        for generator in generator_values[:5]:
            detected.append({
                "name": "HTML generator",
                "score": 100,
                "confidence": 100,
                "confidence_level": "HIGH",
                "signals": [generator[:160]],
            })

    technologies: list[dict[str, object]] = []

    def add_technology(name: str, signals: list[str], confidence: int = 80) -> None:
        if any(item["name"] == name for item in technologies):
            return
        score, level = _confidence(confidence)
        technologies.append({
            "name": name, "confidence": score, "confidence_level": level,
            "signals": signals[:6],
        })

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server:
        lower_server = server.lower()
        for name, pattern in (
            ("Nginx", r"nginx"), ("Apache", r"apache"), ("Caddy", r"caddy"),
            ("Microsoft IIS", r"microsoft-iis"), ("LiteSpeed", r"litespeed"),
            ("OpenResty", r"openresty"),
        ):
            if re.search(pattern, lower_server):
                add_technology(name, [f"Server: {server[:120]}"])
    if powered_by:
        lower = powered_by.lower()
        for name, marker in (("PHP", "php"), ("ASP.NET", "asp.net"), ("Express", "express")):
            if marker in lower:
                add_technology(name, [f"X-Powered-By: {powered_by[:120]}"])
    if "cf-ray" in headers or "cloudflare" in server.lower():
        add_technology("Cloudflare", ["CF-Ray header" if "cf-ray" in headers else "Server header"], 95)
    for name, markers in {
        "Next.js": ("/_next/", "__next_data__"),
        "Nuxt": ("/_nuxt/", "__nuxt__"),
        "React": ("data-reactroot", "react-dom", "react.production.min.js"),
        "Vue.js": ("data-v-app", "__vue__", "vue.runtime"),
        "Angular": ("ng-version=", "angular.js", "platform-browser"),
        "jQuery": ("jquery",),
        "Bootstrap": ("bootstrap.min.css", "bootstrap.min.js"),
    }.items():
        matched = [marker for marker in markers if marker in combined]
        if matched:
            add_technology(name, matched, 90 if len(matched) > 1 else 70)

    detected.sort(key=lambda item: int(item.get("confidence", 0)), reverse=True)
    technologies.sort(key=lambda item: int(item.get("confidence", 0)), reverse=True)
    details = (
        f"HTTP {response.status_code}; detected {len(detected)} CMS/platform signature(s) "
        f"and {len(technologies)} technology signal(s). Fingerprinting is heuristic."
    )
    return [Observation(
        "CMS_FINGERPRINT", "CMS and technology fingerprint", "INFO",
        "DETECTED" if detected or technologies else "NOT_IDENTIFIED",
        response.url, details,
        {
            "http_status": response.status_code,
            "detected": detected,
            "technologies": technologies,
            "generator_values": generator_values[:5],
            "server_header": server[:160] if server else None,
            "x_powered_by": powered_by[:160] if powered_by else None,
            "content_type": headers.get("content-type", ""),
            "fingerprint_method": "weighted public HTML, resource, cookie and response-header signals",
            "limitations": [
                "A site can hide or remove CMS markers.",
                "A reverse proxy or CDN may replace origin response headers.",
                "Signatures may be spoofed; confidence is an estimate, not proof.",
            ],
        },
    )]
