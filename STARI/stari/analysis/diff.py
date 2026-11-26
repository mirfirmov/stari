from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any


def _fingerprint(observation: dict[str, Any]) -> str:
    payload = {
        "severity": observation.get("severity"),
        "status": observation.get("status"),
        "details": observation.get("details"),
        "evidence": observation.get("evidence", {}),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))


def compare_observations(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Compare findings by check ID and target; timestamps and database IDs are ignored."""
    old_map: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
    new_map: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(deque)
    for row in before:
        old_map[(str(row.get("check_id", "")), str(row.get("target", "")))].append(row)
    for row in after:
        new_map[(str(row.get("check_id", "")), str(row.get("target", "")))].append(row)

    result: dict[str, list[dict[str, Any]]] = {
        "new": [], "resolved": [], "changed": [], "unchanged": []
    }
    for key in sorted(set(old_map) | set(new_map)):
        old_rows = old_map.get(key, deque())
        new_rows = new_map.get(key, deque())
        while old_rows and new_rows:
            old = old_rows.popleft()
            new = new_rows.popleft()
            item = {"before": old, "after": new}
            if _fingerprint(old) == _fingerprint(new):
                result["unchanged"].append(item)
            else:
                result["changed"].append(item)
        result["resolved"].extend({"before": row} for row in old_rows)
        result["new"].extend({"after": row} for row in new_rows)
    return result
