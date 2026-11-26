from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from stari.i18n import tr

CONFIG_DIR_NAME = ".stari"
CONFIG_FILE_NAME = "config.json"
PROJECTS_DIR_NAME = "projects"
ACTIVE_PROJECT_FILE = "active_project.json"


@dataclass(slots=True)
class ProjectConfig:
    project_name: str
    base_url: str
    allowed_hosts: list[str]
    user_agent: str = "STARI-CLI/1.0.0 (+authorized security assessment)"
    requests_per_second: float = 1.0
    max_response_bytes: int = 1_048_576
    request_timeout_seconds: float = 12.0

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_target(target: str) -> tuple[str, str]:
    """Return (origin, hostname), accepting either a host or an HTTP(S) URL."""
    candidate = target.strip()
    if not candidate:
        raise ValueError(tr("target_empty"))
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(tr("scheme_unsupported"))
    if not parsed.hostname:
        raise ValueError(tr("hostname_missing"))
    if parsed.username or parsed.password:
        raise ValueError(tr("credentials_disallowed"))
    if parsed.query or parsed.fragment:
        raise ValueError(tr("query_fragment_disallowed"))
    if parsed.path not in {"", "/"}:
        raise ValueError(tr("path_disallowed"))

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError(tr("invalid_hostname")) from exc
    if not hostname or any(ch.isspace() for ch in hostname):
        raise ValueError(tr("invalid_hostname"))

    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    origin = urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))
    return origin, hostname


def workspace_dir(root: Path | None = None) -> Path:
    """The project collection directory for the current working directory."""
    return (root or Path.cwd()) / CONFIG_DIR_NAME


def active_project_path(root: Path | None = None) -> Path:
    return workspace_dir(root) / ACTIVE_PROJECT_FILE


def _active_slug(root: Path | None = None) -> str | None:
    path = active_project_path(root)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        slug = str(data.get("slug", ""))
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ValueError(f"Invalid active project file: {path}") from exc
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", slug):
        raise ValueError("Active project file contains an invalid project identifier.")
    return slug


def project_dir(root: Path | None = None) -> Path:
    """Return the active project's directory, retaining the legacy .stari layout."""
    workspace = workspace_dir(root)
    slug = _active_slug(root)
    if slug is None:
        return workspace
    directory = workspace / PROJECTS_DIR_NAME / slug
    if not (directory / CONFIG_FILE_NAME).is_file():
        raise FileNotFoundError(f"Active STARI project '{slug}' has no config.json.")
    return directory


def config_path(root: Path | None = None) -> Path:
    return project_dir(root) / CONFIG_FILE_NAME


def save_config(config: ProjectConfig, root: Path | None = None) -> Path:
    directory = project_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / CONFIG_FILE_NAME
    path.write_text(json.dumps(config.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_config(root: Path | None = None) -> ProjectConfig:
    path = config_path(root)
    if not path.is_file():
        raise FileNotFoundError(tr("project_not_initialized"))
    data = json.loads(path.read_text(encoding="utf-8"))
    return ProjectConfig(**data)


def make_config(target: str, project_name: str | None = None) -> ProjectConfig:
    origin, hostname = normalize_target(target)
    return ProjectConfig(
        project_name=project_name or hostname,
        base_url=origin,
        allowed_hosts=[hostname],
    )


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return (slug or "project")[:48].rstrip("-") or "project"


def list_projects(root: Path | None = None) -> list[dict[str, object]]:
    """List the legacy default project and all named projects in the workspace."""
    workspace = workspace_dir(root)
    current_slug = _active_slug(root)
    result: list[dict[str, object]] = []
    default_config = workspace / CONFIG_FILE_NAME
    if default_config.is_file():
        try:
            config = ProjectConfig(**json.loads(default_config.read_text(encoding="utf-8")))
            result.append({
                "slug": "default", "project_name": config.project_name,
                "base_url": config.base_url, "path": str(workspace),
                "active": current_slug is None,
            })
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass

    projects_home = workspace / PROJECTS_DIR_NAME
    if projects_home.is_dir():
        for directory in sorted(projects_home.iterdir()):
            config_path = directory / CONFIG_FILE_NAME
            if not directory.is_dir() or not config_path.is_file():
                continue
            try:
                config = ProjectConfig(**json.loads(config_path.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            result.append({
                "slug": directory.name, "project_name": config.project_name,
                "base_url": config.base_url, "path": str(directory),
                "active": current_slug == directory.name,
            })
    return result


def add_project(config: ProjectConfig, root: Path | None = None) -> str:
    """Create a separate project workspace and make it the active project."""
    workspace = workspace_dir(root)
    projects_home = workspace / PROJECTS_DIR_NAME
    projects_home.mkdir(parents=True, exist_ok=True)
    base_slug = _slugify(config.project_name)
    slug = base_slug
    existing = {str(item["slug"]) for item in list_projects(root)}
    if slug in existing or (projects_home / slug).exists():
        digest = hashlib.sha256(f"{config.project_name}\0{config.base_url}".encode()).hexdigest()[:8]
        slug = f"{base_slug[:54]}-{digest}"
        suffix = 2
        while slug in existing or (projects_home / slug).exists():
            slug = f"{base_slug[:50]}-{digest}-{suffix}"
            suffix += 1

    directory = projects_home / slug
    directory.mkdir(parents=True, exist_ok=False)
    (directory / CONFIG_FILE_NAME).write_text(
        json.dumps(config.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    active_project_path(root).write_text(
        json.dumps({"slug": slug}, indent=2), encoding="utf-8"
    )
    return slug


def switch_project(identifier: str, root: Path | None = None) -> dict[str, object]:
    """Switch by slug or display name. 'default' selects the legacy workspace."""
    wanted = identifier.strip().casefold()
    projects = list_projects(root)
    match = next((item for item in projects if str(item["slug"]).casefold() == wanted), None)
    if match is None:
        matches = [item for item in projects if str(item["project_name"]).casefold() == wanted]
        if len(matches) == 1:
            match = matches[0]
        elif len(matches) > 1:
            raise ValueError(f"More than one project is named '{identifier}'; switch using its slug.")
    if match is None:
        raise ValueError(f"Project '{identifier}' was not found. Use 'project list'.")

    active_path = active_project_path(root)
    if match["slug"] == "default":
        active_path.unlink(missing_ok=True)
    else:
        active_path.parent.mkdir(parents=True, exist_ok=True)
        active_path.write_text(json.dumps({"slug": match["slug"]}, indent=2), encoding="utf-8")
    return match
