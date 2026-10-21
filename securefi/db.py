"""SQLite storage. One connection per operation; no global shared connection."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, owner TEXT NOT NULL,
 criticality INTEGER NOT NULL CHECK(criticality BETWEEN 1 AND 5),
 internet_exposed INTEGER NOT NULL CHECK(internet_exposed IN (0,1)),
 environment TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
 asset_id INTEGER NOT NULL REFERENCES assets(id), source TEXT NOT NULL,
 external_id TEXT NOT NULL, location TEXT NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, category TEXT NOT NULL, recommendation TEXT NOT NULL,
 known_exploited INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'open',
 assignee TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '',
 accepted_until TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
 last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS components (
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 ref TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, purl TEXT NOT NULL,
 UNIQUE(asset_id, ref)
);
CREATE TABLE IF NOT EXISTS controls (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, frameworks TEXT NOT NULL,
 owner TEXT NOT NULL DEFAULT '', review_status TEXT NOT NULL DEFAULT 'not_reviewed'
);
CREATE TABLE IF NOT EXISTS evidence (
 id INTEGER PRIMARY KEY, control_id TEXT NOT NULL REFERENCES controls(id),
 finding_id INTEGER REFERENCES findings(id), note TEXT NOT NULL,
 sha256 TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT NOT NULL, details TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_drafts (
 id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
 provider TEXT NOT NULL, model TEXT NOT NULL, fallback_reason TEXT NOT NULL,
 input_sha256 TEXT NOT NULL, input_json TEXT NOT NULL, draft_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', reviewer_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_snapshots (
 id INTEGER PRIMARY KEY, digest TEXT NOT NULL, content TEXT NOT NULL,
 created_at TEXT NOT NULL, chain_id INTEGER, contract_address TEXT,
 tx_hash TEXT, block_number INTEGER
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
PRAGMA user_version=2;
"""


class Database:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError(f"Unsupported database version: {version}")
            conn.executescript("BEGIN IMMEDIATE;\n" + SCHEMA + "\nCOMMIT;")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()
