"""Tenant-scoped document records, durable jobs and hash-linked audit entries.

SQLite is the zero-install profile. PostgreSQL uses the same document envelope
through psycopg, not a second set of inconsistent domain rules.
"""

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    def __init__(self, path="data/platform.db", dsn=None):
        self.path = str(path)
        self.dsn = dsn or os.environ.get("SECUREFI_DATABASE_URL")
        self.postgres = bool(self.dsn)
        if not self.postgres:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS records (tenant TEXT NOT NULL,kind TEXT NOT NULL,id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(tenant,kind,id))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS audit (tenant TEXT NOT NULL,seq INTEGER NOT NULL,payload TEXT NOT NULL,previous TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(tenant,seq))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS jobs (tenant TEXT NOT NULL,id TEXT NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',PRIMARY KEY(tenant,id))"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state)")
            if self.postgres:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS tenant_locks (tenant TEXT PRIMARY KEY)"
                )

    @contextmanager
    def connection(self, tenant=None):
        if self.postgres:
            try:
                import psycopg
            except ImportError:
                raise ValueError(
                    "PostgreSQL profile requires requirements-platform.txt"
                ) from None
            raw = psycopg.connect(self.dsn)

            class Connection:
                def execute(self, sql, params=()):
                    return raw.execute(sql.replace("?", "%s"), params)

            conn = Connection()
        else:
            raw = sqlite3.connect(self.path, timeout=15)
            raw.execute("PRAGMA foreign_keys=ON")
            raw.execute("PRAGMA journal_mode=WAL")
            conn = raw
        try:
            if tenant:
                if self.postgres:
                    conn.execute(
                        "INSERT INTO tenant_locks(tenant) VALUES(?) ON CONFLICT DO NOTHING",
                        (tenant,),
                    )
                    conn.execute(
                        "SELECT tenant FROM tenant_locks WHERE tenant=? FOR UPDATE",
                        (tenant,),
                    )
                else:
                    conn.execute("BEGIN IMMEDIATE")
            yield conn
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()

    def put(self, conn, tenant, kind, value, id_=None):
        id_ = id_ or value.get("id") or uuid4().hex
        item = {**value, "id": id_, "tenant_id": tenant}
        conn.execute(
            "INSERT INTO records(tenant,kind,id,payload) VALUES(?,?,?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET payload=excluded.payload",
            (tenant, kind, id_, canonical(item)),
        )
        return item

    def get(self, tenant, kind, id_, conn=None):
        if conn is None:
            with self.connection() as current:
                return self.get(tenant, kind, id_, current)
        row = conn.execute(
            "SELECT payload FROM records WHERE tenant=? AND kind=? AND id=?",
            (tenant, kind, id_),
        ).fetchone()
        if row is None:
            raise ValueError("Record not found in this tenant")
        return json.loads(row[0])

    def list(self, tenant, kind, conn=None):
        if conn is None:
            with self.connection() as current:
                return self.list(tenant, kind, current)
        return [
            json.loads(r[0])
            for r in conn.execute(
                "SELECT payload FROM records WHERE tenant=? AND kind=? ORDER BY id",
                (tenant, kind),
            ).fetchall()
        ]

    def audit(self, conn, tenant, actor, action, details):
        row = conn.execute(
            "SELECT seq,digest FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1",
            (tenant,),
        ).fetchone()
        sequence, previous = (row[0] + 1, row[1]) if row else (1, "0" * 64)
        payload = canonical(
            {
                "sequence": sequence,
                "tenant": tenant,
                "at": utcnow(),
                "actor": actor,
                "action": action,
                "details": details,
            }
        )
        digest = hashlib.sha256((previous + payload).encode()).hexdigest()
        conn.execute(
            "INSERT INTO audit(tenant,seq,payload,previous,digest) VALUES(?,?,?,?,?)",
            (tenant, sequence, payload, previous, digest),
        )
        return digest

    def verify_audit(self, tenant):
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT seq,payload,previous,digest FROM audit WHERE tenant=? ORDER BY seq",
                (tenant,),
            ).fetchall()
        previous = "0" * 64
        for expected, (seq, payload, stored_previous, digest) in enumerate(rows, 1):
            if (
                seq != expected
                or stored_previous != previous
                or hashlib.sha256((previous + payload).encode()).hexdigest() != digest
            ):
                return {"valid": False, "failed_sequence": seq, "entries": len(rows)}
            previous = digest
        return {
            "valid": True,
            "entries": len(rows),
            "head": previous,
            "limitation": "External checkpoint required to detect suffix truncation or full-chain rewriting.",
        }

    def enqueue(self, conn, tenant, payload):
        id_ = uuid4().hex
        conn.execute(
            "INSERT INTO jobs(tenant,id,state,payload) VALUES(?,?,?,?)",
            (tenant, id_, "pending", canonical(payload)),
        )
        return id_
