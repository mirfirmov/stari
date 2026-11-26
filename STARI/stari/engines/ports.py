from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from stari.core.models import Observation


COMMON_WEB_PORTS = (80, 443, 8000, 8080, 8081, 8443, 8888, 9000)


async def check_ports(
    hostname: str,
    base_url: str,
    *,
    timeout: float = 3.0,
    requests_per_second: float = 1.0,
    ports: tuple[int, ...] = COMMON_WEB_PORTS,
    allowed_hosts: tuple[str, ...] | list[str] | None = None,
) -> list[Observation]:
    parsed = urlsplit(base_url)
    normalized_host = hostname.encode("idna").decode("ascii").lower().rstrip(".") if hostname else ""
    target_host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    normalized_allowed = {
        item.encode("idna").decode("ascii").lower().rstrip(".")
        for item in (allowed_hosts if allowed_hosts is not None else [target_host])
    }
    if not normalized_host or normalized_host != target_host or normalized_host not in normalized_allowed:
        return [Observation(
            "PORT_SCAN_INVALID_HOST", "Invalid host for port check", "INFO", "ERROR",
            base_url, "The host could not be normalized.", {},
        )]

    hostname = normalized_host
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    selected_ports = tuple(dict.fromkeys((target_port, *ports)))
    if any(not isinstance(port, int) or port < 1 or port > 65535 for port in selected_ports):
        raise ValueError("Invalid TCP port in the configured web-port list.")

    interval = 1.0 / max(requests_per_second, 0.1)
    last_attempt = 0.0
    results: list[dict[str, object]] = []

    for port in selected_ports:
        now = time.monotonic()
        delay = interval - (now - last_attempt)
        if last_attempt and delay > 0:
            await asyncio.sleep(delay)
        last_attempt = time.monotonic()
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=max(0.2, timeout)
            )
            results.append({"port": port, "state": "OPEN", "service_hint": _service_hint(port)})
        except asyncio.TimeoutError:
            results.append({"port": port, "state": "FILTERED_OR_TIMEOUT", "service_hint": _service_hint(port)})
        except (ConnectionRefusedError, OSError) as exc:
            results.append({"port": port, "state": "CLOSED_OR_UNREACHABLE", "error": type(exc).__name__, "service_hint": _service_hint(port)})
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    opened = [item for item in results if item["state"] == "OPEN"]
    return [Observation(
        "WEB_TCP_PORTS", "Common web TCP ports", "INFO", "OBSERVED",
        base_url,
        f"Checked {len(results)} common web ports on {hostname}; {len(opened)} responded to TCP connection attempts.",
        {"hostname": hostname, "ports": results, "open_ports": [item["port"] for item in opened],
         "scan_type": "TCP connect", "port_scope": "fixed common web ports only"},
    )]


def _service_hint(port: int) -> str:
    return {
        80: "HTTP", 443: "HTTPS", 8000: "HTTP-alt", 8080: "HTTP-proxy/alt",
        8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP-alt",
    }.get(port, "unknown")
