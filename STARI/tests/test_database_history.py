from stari.core.database import Database
from stari.core.models import Observation


def test_get_observation_finds_old_scans(tmp_path):
    db = Database(tmp_path / "stari.sqlite3")
    first = db.start_scan("https://example.com", "dns")
    db.save_observations(first, [Observation(
        "DNS_A_RECORDS", "DNS A records", "INFO", "OBSERVED",
        "https://example.com", "192.0.2.10", {"records": ["192.0.2.10"]},
    )])
    db.finish_scan(first)

    second = db.start_scan("https://example.com", "headers")
    db.save_observations(second, [Observation(
        "HTTP_ROOT_RESPONSE", "Root response", "INFO", "OBSERVED",
        "https://example.com", "HTTP 200", {"http_status": 200},
    )])
    db.finish_scan(second)

    old_observation = db.get_observation(1)
    assert old_observation is not None
    assert old_observation["scan_id"] == first
    assert old_observation["scan_mode"] == "dns"
    assert old_observation["evidence"]["records"] == ["192.0.2.10"]
