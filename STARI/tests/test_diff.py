from stari.analysis.diff import compare_observations


def row(check_id, status, details="same", evidence=None, db_id=1):
    return {
        "id": db_id, "check_id": check_id, "target": "https://example.com",
        "severity": "INFO", "status": status, "details": details,
        "evidence": evidence or {},
    }


def test_diff_categorizes_new_resolved_changed_and_unchanged():
    before = [
        row("A", "OBSERVED"), row("B", "OBSERVED"),
        row("C", "NEEDS_REVIEW"),
    ]
    after = [
        row("A", "OBSERVED", db_id=99),
        row("B", "RESOLVED", details="updated"),
        row("D", "DETECTED"),
    ]
    result = compare_observations(before, after)
    assert [item["after"]["check_id"] for item in result["unchanged"]] == ["A"]
    assert [item["before"]["check_id"] for item in result["resolved"]] == ["C"]
    assert [item["after"]["check_id"] for item in result["changed"]] == ["B"]
    assert [item["after"]["check_id"] for item in result["new"]] == ["D"]


def test_diff_ignores_database_ids_and_created_timestamps():
    old = row("A", "OBSERVED", db_id=1)
    new = row("A", "OBSERVED", db_id=500)
    old["created_at"] = "2026-01-01"
    new["created_at"] = "2026-02-01"
    result = compare_observations([old], [new])
    assert len(result["unchanged"]) == 1
