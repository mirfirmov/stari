from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from stari.core.config import ProjectConfig
from stari.core.models import Observation
from stari.engines.headers import check_headers
from stari.engines.crawler import check_crawler
from stari.engines.security import check_cors
from stari.engines.admin_finder import check_admin_panels
from stari.engines.cms import check_cms
from stari.engines.emails import check_emails
from stari.engines.ports import check_ports
from stari.engines.http_client import SafeHTTPClient
from stari.engines.network import check_dns, check_tls
from stari.engines.whois import check_whois
from stari.engines.robots import check_robots
from stari.engines.sitemap import check_sitemap
from stari.engines.subdomains import check_subdomains
from stari.engines.parameter_audit import check_sqli_boolean_and_error, check_xss_reflection


class ReconEngine:
    """Run baseline checks, optionally including bounded extended discovery."""

    def __init__(self, config: ProjectConfig):
        self.config = config
        parsed_target = urlsplit(config.base_url)
        self.hostname = parsed_target.hostname or ""
        self.port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

    async def run(self, *, include_extended: bool = False, include_vuln: bool = False) -> list[Observation]:
        async with SafeHTTPClient(self.config) as client:
            jobs = [
                ("headers", check_headers(client, self.config.base_url)),
                ("cors", check_cors(client, self.config.base_url)),
                ("robots", check_robots(client, self.config.base_url)),
                ("sitemap", check_sitemap(client, self.config.base_url)),
                ("dns", check_dns(
                    self.hostname, self.config.base_url,
                    requests_per_second=self.config.requests_per_second,
                )),
                ("tls", check_tls(
                    self.hostname, self.config.base_url, self.port,
                    timeout=self.config.request_timeout_seconds,
                )),
                ("whois", check_whois(
                    self.hostname, self.config.base_url,
                    timeout=self.config.request_timeout_seconds,
                    max_response_bytes=self.config.max_response_bytes,
                    user_agent=self.config.user_agent,
                    requests_per_second=self.config.requests_per_second,
                )),
            ]
            if include_extended:
                jobs.extend([
                    ("subdomains", check_subdomains(self.config)),
                    ("admin", check_admin_panels(client, self.config.base_url)),
                    ("emails", check_emails(client, self.config.base_url)),
                    ("cms", check_cms(client, self.config.base_url)),
                    ("crawler", check_crawler(client, self.config.base_url)),
                    ("ports", check_ports(
                        self.hostname, self.config.base_url,
                        timeout=min(self.config.request_timeout_seconds, 3.0),
                        requests_per_second=self.config.requests_per_second,
                        allowed_hosts=self.config.allowed_hosts,
                    )),
                ])
            if include_vuln:
                jobs.extend([
                    ("xss", check_xss_reflection(client, self.config.base_url)),
                    ("sqli", check_sqli_boolean_and_error(client, self.config.base_url)),
                ])
            results = await asyncio.gather(
                *(job for _, job in jobs), return_exceptions=True
            )

        observations: list[Observation] = []
        for (engine_name, _), result in zip(jobs, results, strict=True):
            if isinstance(result, Exception):
                observations.append(Observation(
                    f"{engine_name.upper()}_ENGINE_ERROR",
                    f"{engine_name.title()} engine failed", "INFO", "ERROR",
                    self.config.base_url,
                    f"{type(result).__name__}: {result}",
                    {"engine": engine_name, "error_type": type(result).__name__},
                ))
            else:
                observations.extend(result)
        return observations
