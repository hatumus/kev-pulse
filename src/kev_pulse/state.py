"""SQLite-backed state store.

Holds three things that must survive a restart:
  1. feed cursors (where each watcher left off),
  2. a durable index of every CVE -> plugin(s) we've ever seen, and every
     CVE CISA has ever added to KEV -- so correlation works regardless of
     whether the plugin or the KEV entry showed up first, and
  3. a full audit trail of every proposed and launched scan.

SQLite is deliberately used for the default/small-deployment case; swap the
connection string for a Postgres DSN and this module is the only thing that
would need a driver change (schema is plain ANSI SQL).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from .models import KevEntry, Plugin, utcnow_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS cursors (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_cves (
    cve_id TEXT PRIMARY KEY,
    date_added TEXT NOT NULL,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    raw_json TEXT,
    first_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugin_cve_index (
    cve_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    plugin_name TEXT,
    family TEXT,
    cvss3_base_score REAL,
    last_updated TEXT,
    first_seen_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, plugin_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- proposed | launched | rejected | dry_run
    cve_id TEXT,
    plugin_id TEXT,
    tags TEXT,                  -- JSON list
    backend TEXT,
    scan_id TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS scan_plans (
    plan_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    plugin_name TEXT,
    plugin_family TEXT,
    tags TEXT NOT NULL,          -- JSON list
    backend TEXT NOT NULL,
    policy_template_id TEXT,
    created_at TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);
"""


class StateStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _cursor(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
                self._conn.commit()
            finally:
                cur.close()

    # ---- cursors ---------------------------------------------------

    def get_cursor(self, name: str) -> Optional[str]:
        with self._cursor() as cur:
            row = cur.execute("SELECT value FROM cursors WHERE name = ?", (name,)).fetchone()
            return row["value"] if row else None

    def set_cursor(self, name: str, value: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO cursors(name, value) VALUES (?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                (name, value),
            )

    # ---- KEV -------------------------------------------------------

    def upsert_kev(self, entries: Iterable[KevEntry]) -> list[str]:
        """Insert any KEV entries not already known. Returns the list of
        CVE IDs that were genuinely new (i.e. the delta), not the full set."""
        new_cve_ids: list[str] = []
        with self._cursor() as cur:
            for e in entries:
                row = cur.execute(
                    "SELECT 1 FROM kev_cves WHERE cve_id = ?", (e.cve_id,)
                ).fetchone()
                if row is not None:
                    continue
                cur.execute(
                    "INSERT INTO kev_cves(cve_id, date_added, vendor_project, product, "
                    "vulnerability_name, raw_json, first_seen_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        e.cve_id,
                        e.date_added,
                        e.vendor_project,
                        e.product,
                        e.vulnerability_name,
                        json.dumps(e.__dict__),
                        utcnow_iso(),
                    ),
                )
                new_cve_ids.append(e.cve_id)
        return new_cve_ids

    def is_kev(self, cve_id: str) -> bool:
        with self._cursor() as cur:
            row = cur.execute("SELECT 1 FROM kev_cves WHERE cve_id = ?", (cve_id,)).fetchone()
            return row is not None

    # ---- plugins -----------------------------------------------------

    def upsert_plugins(self, plugins: Iterable[Plugin]) -> list[tuple[str, Plugin]]:
        """Record every (cve, plugin) pair. Returns the list of pairs that
        were genuinely new (not previously indexed) -- the plugin-arrived-
        first direction of correlation."""
        new_pairs: list[tuple[str, Plugin]] = []
        with self._cursor() as cur:
            for p in plugins:
                for cve in p.cves:
                    row = cur.execute(
                        "SELECT 1 FROM plugin_cve_index WHERE cve_id = ? AND plugin_id = ?",
                        (cve, p.plugin_id),
                    ).fetchone()
                    if row is not None:
                        # still refresh last_updated/cvss in case the plugin was revised
                        cur.execute(
                            "UPDATE plugin_cve_index SET last_updated = ?, cvss3_base_score = ? "
                            "WHERE cve_id = ? AND plugin_id = ?",
                            (p.last_updated, p.cvss3_base_score, cve, p.plugin_id),
                        )
                        continue
                    cur.execute(
                        "INSERT INTO plugin_cve_index(cve_id, plugin_id, plugin_name, family, "
                        "cvss3_base_score, last_updated, first_seen_at) VALUES (?,?,?,?,?,?,?)",
                        (
                            cve,
                            p.plugin_id,
                            p.name,
                            p.family,
                            p.cvss3_base_score,
                            p.last_updated,
                            utcnow_iso(),
                        ),
                    )
                    new_pairs.append((cve, p))
        return new_pairs

    def get_plugins_for_cve(self, cve_id: str) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT * FROM plugin_cve_index WHERE cve_id = ?", (cve_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- scan plans --------------------------------------------------

    def save_scan_plan(self, plan) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO scan_plans(plan_id, cve_id, plugin_id, plugin_name, plugin_family, "
                "tags, backend, policy_template_id, created_at, consumed) VALUES (?,?,?,?,?,?,?,?,?,0)",
                (
                    plan.plan_id,
                    plan.cve_id,
                    plan.plugin_id,
                    plan.plugin_name,
                    plan.plugin_family,
                    json.dumps(plan.tags),
                    plan.backend,
                    plan.policy_template_id,
                    plan.created_at,
                ),
            )

    def get_scan_plan(self, plan_id: str) -> Optional[dict]:
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT * FROM scan_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                return None
            d = dict(row)
            d["tags"] = json.loads(d["tags"])
            return d

    def mark_scan_plan_consumed(self, plan_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE scan_plans SET consumed = 1 WHERE plan_id = ?", (plan_id,))

    # ---- audit / rate limiting ----------------------------------------

    def record_audit(
        self,
        event_type: str,
        cve_id: str = "",
        plugin_id: str = "",
        tags: Optional[list[str]] = None,
        backend: str = "",
        scan_id: str = "",
        detail: str = "",
    ) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log(ts, event_type, cve_id, plugin_id, tags, backend, "
                "scan_id, detail) VALUES (?,?,?,?,?,?,?,?)",
                (
                    utcnow_iso(),
                    event_type,
                    cve_id,
                    plugin_id,
                    json.dumps(tags or []),
                    backend,
                    scan_id,
                    detail,
                ),
            )

    def count_launches_since(self, since_hours: float) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat(
            timespec="seconds"
        )
        with self._cursor() as cur:
            row = cur.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE event_type = 'launched' AND ts >= ?",
                (cutoff,),
            ).fetchone()
            return int(row["n"])

    def get_audit_history(self, limit: int = 100) -> list[dict]:
        with self._cursor() as cur:
            rows = cur.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["tags"] = json.loads(d["tags"]) if d["tags"] else []
                out.append(d)
            return out
