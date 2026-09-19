"""SQLite persistence for AstraSec: request log, immune memory, learned signatures, policy and audit trail.

One process-wide RLock serialises access; SQLite is more than fast enough for a single-node deployment and keeps the
project dependency-free.  Every mutation of the system's own defences (policy, thresholds, signatures, retraining)
is written to `adaptations` so the self-healing behaviour is fully auditable.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, client TEXT, app TEXT, prompt TEXT,
    label TEXT, flagged INTEGER, attack_conf REAL, severity TEXT, severity_score REAL, anomaly REAL,
    risk REAL, action TEXT, allowed INTEGER, defense_success INTEGER, memory_id INTEGER, memory_sim REAL,
    emerging INTEGER DEFAULT 0, leak_caught INTEGER DEFAULT 0, health REAL, latency_ms REAL,
    feedback TEXT, trace TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, last_seen REAL, prompt TEXT, normalized TEXT, label TEXT,
    severity TEXT, confidence REAL, action TEXT, hits INTEGER DEFAULT 1, successes INTEGER DEFAULT 0,
    failures INTEGER DEFAULT 0, last_success INTEGER, sig_hits INTEGER DEFAULT 0, source TEXT, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS signatures (
    sid TEXT PRIMARY KEY, label TEXT, pattern TEXT, weight REAL, source TEXT, status TEXT, created REAL,
    fp_reports INTEGER DEFAULT 0, note TEXT);
CREATE TABLE IF NOT EXISTS policy (key TEXT PRIMARY KEY, action TEXT);
CREATE TABLE IF NOT EXISTS adaptations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, summary TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(self.path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        with self._lock:
            self._con.executescript(SCHEMA)
            self._con.commit()

    # ---------------------------------------------------------------- primitives
    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self._lock:
            cur = self._con.execute(sql, params)
            self._con.commit()
            return cur.lastrowid or 0

    def query(self, sql: str, params: tuple | list = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._con.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple | list = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: tuple | list = (), default: Any = 0) -> Any:
        with self._lock:
            row = self._con.execute(sql, params).fetchone()
        return default if row is None or row[0] is None else row[0]

    # ---------------------------------------------------------------- kv / policy
    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def kv_set(self, key: str, value: Any) -> None:
        self.execute("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, json.dumps(value)))

    def policy_load(self) -> dict[str, str]:
        return {r["key"]: r["action"] for r in self.query("SELECT key, action FROM policy")}

    def policy_set(self, key: str, action: str) -> None:
        self.execute("INSERT INTO policy(key,action) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET action=excluded.action",
                     (key, action))

    # ---------------------------------------------------------------- audit trail
    def log_adaptation(self, kind: str, summary: str, detail: dict | None = None) -> int:
        return self.execute("INSERT INTO adaptations(ts,kind,summary,detail) VALUES(?,?,?,?)",
                            (time.time(), kind, summary, json.dumps(detail or {})))

    def adaptations(self, limit: int = 100) -> list[dict]:
        rows = self.query("SELECT * FROM adaptations ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["detail"] = json.loads(r["detail"] or "{}")
        return rows

    # ---------------------------------------------------------------- events
    def add_event(self, **f: Any) -> int:
        cols = ",".join(f.keys())
        qs = ",".join("?" for _ in f)
        return self.execute(f"INSERT INTO events({cols}) VALUES({qs})", tuple(f.values()))

    def recent_events(self, limit: int = 100, since: float | None = None, label: str | None = None,
                      flagged: bool | None = None, with_trace: bool = False) -> list[dict]:
        cols = "*" if with_trace else ("id,ts,client,app,prompt,label,flagged,attack_conf,severity,severity_score,anomaly,risk,"
                                       "action,allowed,defense_success,memory_id,memory_sim,emerging,leak_caught,health,latency_ms,feedback")
        where, params = [], []
        if since is not None:
            where.append("ts>=?"); params.append(since)
        if label:
            where.append("label=?"); params.append(label)
        if flagged is not None:
            where.append("flagged=?"); params.append(1 if flagged else 0)
        sql = f"SELECT {cols} FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        rows = self.query(sql, params + [limit])
        if with_trace:
            for r in rows:
                r["trace"] = json.loads(r["trace"] or "{}")
        return rows

    def get_event(self, event_id: int) -> dict | None:
        r = self.one("SELECT * FROM events WHERE id=?", (event_id,))
        if r:
            r["trace"] = json.loads(r["trace"] or "{}")
        return r

    def close(self) -> None:
        with self._lock:
            self._con.close()
