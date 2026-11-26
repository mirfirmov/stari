from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def export_report(scan: dict, observations: list[dict], output: Path, fmt: str) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "project": "stari cli",
        "scan": scan,
        "observations": observations,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "note": "observations require contextual review; they are not automatically confirmed vulnerabilities.",
    }
    if fmt == "json":
        output.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        lines = [
            "# stari cli report",
            "",
            f"- target: `{scan['target']}`",
            f"- scan id: `{scan['id']}`",
            f"- mode: `{scan['mode']}`",
            f"- started: `{scan['started_at']}`",
            f"- finished: `{scan.get('finished_at') or 'unknown'}`",
            "",
            "> observations need contextual review. they are not automatically confirmed vulnerabilities.",
            "",
            "## observations",
            "",
        ]
        if not observations:
            lines.append("no observations recorded.")
        for item in observations:
            lines.extend([
                f"### {item['title']}",
                f"- id: `{item['check_id']}`",
                f"- severity: **{item['severity']}**",
                f"- status: `{item['status']}`",
                f"- target: `{item['target']}`",
                f"- details: {item['details']}",
                "",
                "evidence:",
                "```json",
                json.dumps(item.get("evidence", {}), indent=2, ensure_ascii=False),
                "```",
                "",
            ])
        output.write_text("\n".join(lines), encoding="utf-8")
    return output
