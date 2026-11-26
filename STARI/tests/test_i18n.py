from stari.i18n import choose_language, current_language, load_saved_language, tr


def test_choose_russian_and_persist(tmp_path):
    pref = tmp_path / "preferences.json"
    selected = choose_language("ru", preference_file=pref, output_fn=lambda _: None)
    assert selected == "ru"
    assert current_language() == "ru"
    assert load_saved_language(pref) == "ru"
    assert tr("target") == "цель"


def test_choose_english_and_persist(tmp_path):
    pref = tmp_path / "preferences.json"
    selected = choose_language("en", preference_file=pref, output_fn=lambda _: None)
    assert selected == "en"
    assert current_language() == "en"
    assert load_saved_language(pref) == "en"
    assert tr("target") == "target"


def test_default_prompt_selects_russian(tmp_path):
    pref = tmp_path / "preferences.json"
    selected = choose_language(
        input_fn=lambda _: "1",
        output_fn=lambda _: None,
        preference_file=pref,
    )
    assert selected == "ru"
