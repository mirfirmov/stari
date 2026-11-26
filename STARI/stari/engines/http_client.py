from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlsplit

import httpx

from stari.core.config import ProjectConfig
from stari.core.models import HTTPResult
from stari.core.scope import is_in_scope, require_in_scope


class SafeHTTPClient:
    """Small, rate-limited HTTP client restricted to the configured scope."""

    def __init__(self, config: ProjectConfig):
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._pace_lock = asyncio.Lock()
        self._last_request_at = 0.0

    async def __aenter__(self) -> "SafeHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.request_timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": self.config.user_agent, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        )
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _pace(self) -> None:
        interval = 1.0 / max(self.config.requests_per_second, 0.1)
        async with self._pace_lock:
            now = time.monotonic()
            delay = interval - (now - self._last_request_at)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_request_at = time.monotonic()

    async def get(self, url: str, *, extra_headers: dict[str, str] | None = None) -> HTTPResult:
        """GET an in-scope URL; only the Origin header may be overridden for CORS audits."""
        if self._client is None:
            raise RuntimeError("HTTP client is not open.")

        safe_headers: dict[str, str] = {}
        if extra_headers:
            for name, value in extra_headers.items():
                if name.lower() != "origin":
                    raise ValueError("Only the Origin header is allowed as an extra request header.")
                if "\r" in value or "\n" in value:
                    raise ValueError("Invalid request header value.")
                safe_headers["Origin"] = value[:256]

        current_url = url
        redirect_history: list[dict[str, object]] = []
        redirect_codes = {301, 302, 303, 307, 308}


        for hop in range(6):
            require_in_scope(current_url, self.config)
            await self._pace()

            request_context = (
                self._client.stream("GET", current_url, headers=safe_headers)
                if safe_headers else self._client.stream("GET", current_url)
            )
            async with request_context as response:
                location = response.headers.get("location")
                if response.status_code in redirect_codes and location:
                    redirect_url = urljoin(str(response.url), location)
                    if is_in_scope(redirect_url, self.config):
                        redirect_history.append({
                            "status_code": response.status_code,
                            "from": str(response.url),
                            "to": redirect_url,
                        })
                        if hop == 5:
                            raise RuntimeError("Redirect limit reached (maximum 5 redirects).")
                        current_url = redirect_url
                        continue

                body = bytearray()
                truncated = False
                max_bytes = max(1, self.config.max_response_bytes)
                async for chunk in response.aiter_bytes():
                    remaining = max_bytes - len(body)
                    if len(chunk) > remaining:
                        body.extend(chunk[:remaining])
                        truncated = True
                        break
                    body.extend(chunk)

                headers = {key.lower(): value for key, value in response.headers.items()}
                header_items = list(response.headers.multi_items()) if hasattr(response.headers, "multi_items") else list(response.headers.items())
                return HTTPResult(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=headers,
                    body=bytes(body),
                    truncated=truncated,
                    redirect_history=redirect_history,
                    header_items=header_items,
                )

        raise RuntimeError("Redirect processing ended unexpectedly.")



def origin_for_url(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"
