from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class Observation:
    """A recorded observation; it is not automatically a confirmed vulnerability."""

    check_id: str
    title: str
    severity: str
    status: str
    target: str
    details: str
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HTTPResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False
    redirect_history: list[dict[str, Any]] = field(default_factory=list)
    header_items: list[tuple[str, str]] = field(default_factory=list)

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        encoding = "utf-8"
        for part in content_type.split(";")[1:]:
            if "charset=" in part.lower():
                encoding = part.split("=", 1)[1].strip().strip('"\'')
                break
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")
