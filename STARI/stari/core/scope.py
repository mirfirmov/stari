from __future__ import annotations

from urllib.parse import urlsplit

from stari.core.config import ProjectConfig
from stari.i18n import tr


def is_in_scope(url: str, config: ProjectConfig) -> bool:
    """Only allow HTTP(S) URLs whose hostname is explicitly in the project scope."""
    try:
        parsed = urlsplit(url)
        base = urlsplit(config.base_url)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        allowed_hosts = {
            item.encode("idna").decode("ascii").lower().rstrip(".")
            for item in config.allowed_hosts
        }
        effective_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        base_port = base.port or (443 if base.scheme.lower() == "https" else 80)
        return (
            parsed.scheme.lower() == base.scheme.lower()
            and host in allowed_hosts
            and effective_port == base_port
            and parsed.username is None
            and parsed.password is None
        )
    except (ValueError, UnicodeError):
        return False


def require_in_scope(url: str, config: ProjectConfig) -> None:
    if not is_in_scope(url, config):
        raise ValueError(tr("out_of_scope", url=url))
