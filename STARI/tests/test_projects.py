import json

import pytest

from stari.core.config import (
    add_project, list_projects, load_config, make_config, project_dir,
    switch_project,
)
from stari.core.database import Database


def test_add_project_creates_independent_workspace_and_activates_it(tmp_path):
    legacy = make_config("https://legacy.example", "legacy")
    from stari.core.config import save_config
    save_config(legacy, tmp_path)

    slug = add_project(make_config("https://parovoz.tv", "parovoz"), tmp_path)
    assert slug == "parovoz"
    assert project_dir(tmp_path).name == "parovoz"
    assert load_config(tmp_path).base_url == "https://parovoz.tv"
    Database(project_dir(tmp_path) / "stari.sqlite3")
    rows = list_projects(tmp_path)
    assert len(rows) == 2
    assert next(item for item in rows if item["slug"] == "parovoz")["active"] is True


def test_switching_between_named_and_legacy_project(tmp_path):
    from stari.core.config import save_config
    save_config(make_config("https://legacy.example", "legacy"), tmp_path)
    slug = add_project(make_config("https://other.example", "other"), tmp_path)
    switch_project("legacy", tmp_path)
    assert project_dir(tmp_path) == tmp_path / ".stari"
    assert load_config(tmp_path).base_url == "https://legacy.example"
    switch_project(slug, tmp_path)
    assert load_config(tmp_path).base_url == "https://other.example"


def test_duplicate_project_names_get_safe_unique_slugs(tmp_path):
    first = add_project(make_config("https://one.example", "same name"), tmp_path)
    second = add_project(make_config("https://two.example", "same name"), tmp_path)
    assert first != second
    assert all("/" not in str(item["slug"]) for item in list_projects(tmp_path))


def test_switch_unknown_project_errors(tmp_path):
    with pytest.raises(ValueError):
        switch_project("missing", tmp_path)
