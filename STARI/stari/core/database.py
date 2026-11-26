from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from stari.core.models import Observation, utc_now


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    observation_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target TEXT NOT NULL,
                    details TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_observations_scan_id
                    ON observations(scan_id);
                """
            )

    def start_scan(self, target: str, mode: str) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scans(target, mode, started_at) VALUES (?, ?, ?)",
                (target, mode, utc_now()),
            )
            return int(cursor.lastrowid)

    def save_observations(self, scan_id: int, observations: list[Observation]) -> None:
        if not observations:
            return
        rows = [
            (
                scan_id,
                item.check_id,
                item.title,
                item.severity,
                item.status,
                item.target,
                item.details,
                json.dumps(item.evidence, ensure_ascii=False),
                item.created_at,
            )
            for item in observations
        ]
        with self._connect() as connection:
            connection.executemany(
                """INSERT INTO observations
                (scan_id, check_id, title, severity, status, target,
                 details, evidence_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
            connection.execute(
                "UPDATE scans SET observation_count = ? WHERE id = ?",
                (len(observations), scan_id),
            )

    def finish_scan(self, scan_id: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE scans SET finished_at = ? WHERE id = ?",
                (utc_now(), scan_id),
            )

    def latest_scan(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None


    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_observation(self, observation_id: int) -> dict[str, Any] | None:
        """Fetch one observation from any scan, not only the latest scan."""
        with self._connect() as connection:
            row = connection.execute(
                """SELECT o.*, s.mode AS scan_mode, s.target AS scan_target,
                          s.started_at AS scan_started_at
                   FROM observations AS o
                   JOIN scans AS s ON s.id = o.scan_id
                   WHERE o.id = ?""",
                (observation_id,),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            result["evidence"] = json.loads(result.pop("evidence_json"))
            return result

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def list_observations(self, scan_id: int | None = None) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if scan_id is None:
                scan = connection.execute(
                    "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if not scan:
                    return []
                scan_id = int(scan["id"])
            rows = connection.execute(
                "SELECT * FROM observations WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
            results = [dict(row) for row in rows]
            for item in results:
                item["evidence"] = json.loads(item.pop("evidence_json"))
            return results
