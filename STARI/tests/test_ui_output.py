from io import StringIO

from rich.console import Console

import stari.ui as ui


def test_observation_details_render_remote_markup_literally(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=240, force_terminal=False, color_system=None))

    ui.observations_table([{
        "id": 1,
        "severity": "INFO",
        "status": "OBSERVED",
        "title": "Page title [bold red]not markup[/bold red]",
        "details": "Header value [link=https://example.invalid]click[/link]",
    }])

    rendered = output.getvalue()
    assert "[bold red]not markup[/bold red]" in rendered
    assert "[link=https://example.invalid]click[/link]" in rendered


def test_key_value_panel_renders_values_literally(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=240, force_terminal=False, color_system=None))

    ui.key_value_panel("Details", {"Remote header": "[red]injected[/red]"})

    assert "[red]injected[/red]" in output.getvalue()


def test_inspection_panel_renders_remote_text_literally(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=240, force_terminal=False, color_system=None))

    ui.render_observation_detail({
        "id": 4,
        "title": "[bold]remote title[/bold]",
        "check_id": "TEST",
        "scan_id": 1,
        "scan_mode": "recon",
        "severity": "INFO",
        "status": "OBSERVED",
        "target": "https://example.invalid",
        "details": "[red]untrusted response[/red]",
        "evidence": {},
    })

    rendered = output.getvalue()
    assert "[bold]remote title[/bold]" in rendered
    assert "[red]untrusted response[/red]" in rendered


def test_admin_details_show_observed_login_pages_separately(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=240, force_terminal=False, color_system=None))
    monkeypatch.setattr(ui, "current_language", lambda: "ru")

    ui._show_admin_details([{
        "evidence": {
            "candidates": [],
            "login_pages": [{
                "path": "/private-area",
                "source": "homepage-link: Войти",
                "http_status": 200,
                "confidence": "MEDIUM",
                "classification": "observed_admin_login_unverified",
                "evidence_reasons": ["email identity control", "visible login cue", "submit control"],
                "final_url": "https://example.com/private-area",
            }],
            "login_page_count": 1,
            "external_redirects": [],
            "robots_admin_path_hint_count": 0,
            "checked_paths": 1,
            "verified_count": 0,
            "soft_404_filtered": 0,
            "restricted_unverified_count": 0,
            "weak_signal_ignored_count": 0,
            "baseline_stable": True,
        }
    }])

    rendered = output.getvalue()
    assert "обнаруженные страницы входа" in rendered
    assert "/private-area" in rendered
    assert "homepage-link: Войти" in rendered
    assert "observed_admin_login_unverified" in rendered
    assert "страниц входа: 1" in rendered
    assert "подтверждённых админ-панелей не найдено" in rendered


def test_admin_details_show_login_pages_and_out_of_scope_links_separately(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=240, force_terminal=False, color_system=None))
    monkeypatch.setattr(ui, "current_language", lambda: "ru")

    ui._show_admin_details([{
        "evidence": {
            "candidates": [],
            "login_pages": [{
                "path": "/private-area",
                "source": "homepage-link: Войти",
                "http_status": 200,
                "confidence": "MEDIUM",
                "evidence_reasons": ["email identity control", "visible login cue", "submit control"],
                "final_url": "https://example.com/private-area",
            }],
            "login_page_count": 1,
            "external_redirects": [],
            "external_login_links": [{
                "label": "Войти",
                "host": "auth.example.net",
                "destination": "https://auth.example.net/sign-in",
            }],
            "related_subdomain_links": [{
                "host": "blog.example.com",
                "label": "Блог",
                "path": "/",
            }],
            "robots_admin_path_hint_count": 0,
            "checked_paths": 1,
            "verified_count": 0,
            "soft_404_filtered": 0,
            "restricted_unverified_count": 0,
            "weak_signal_ignored_count": 0,
            "baseline_stable": True,
        }
    }])

    rendered = output.getvalue()
    assert "обнаруженные страницы входа" in rendered
    assert "/private-area" in rendered
    assert "ссылки на вход вне scope" in rendered
    assert "auth.example.net" in rendered
    assert "ссылки на поддомены вне scope" in rendered
    assert "blog.example.com" in rendered
