from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Iterable, Dict, Any, Optional
from datetime import datetime, timezone
import json

SCHEMA = """
CREATE TABLE IF NOT EXISTS cert_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,           -- sha256 of cert
    source TEXT NOT NULL,                -- filesystem/aws/...
    location TEXT,                       -- path for filesystem, arn/id for cloud
    subject TEXT,
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    sans_json TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(fingerprint, source, location)
);

CREATE INDEX IF NOT EXISTS idx_cert_inventory_expiry ON cert_inventory(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_inventory_source ON cert_inventory(source);
"""

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class Inventory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        # Return dict-ish rows
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self):
        with self._conn:
            self._conn.executescript(SCHEMA)

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def upsert_many(self, rows: Iterable[Dict[str, Any]]) -> int:
        """
        Insert or update discovered rows.
        Expected keys:
          fingerprint, source, location, subject, issuer, not_before, not_after, sans (list[str])
        """
        now = utcnow_iso()
        count = 0
        with self._conn:
            for r in rows:
                sans_json = json.dumps(r.get("sans", []) or [])
                data = {
                    "fingerprint": r["fingerprint"],
                    "source": r["source"],
                    "location": r.get("path") or r.get("location") or "",
                    "subject": r.get("subject"),
                    "issuer": r.get("issuer"),
                    "not_before": r.get("not_before"),
                    "not_after": r.get("not_after"),
                    "sans_json": sans_json,
                    "ts": now,
                }
                # Try update first; if no row updated, insert
                updated = self._conn.execute(
                    """UPDATE cert_inventory
                       SET subject=:subject,
                           issuer=:issuer,
                           not_before=:not_before,
                           not_after=:not_after,
                           sans_json=:sans_json,
                           last_seen=:ts
                       WHERE fingerprint=:fingerprint
                         AND source=:source
                         AND location=:location
                    """,
                    data,
                )
                if updated.rowcount == 0:
                    self._conn.execute(
                        """INSERT OR IGNORE INTO cert_inventory
                           (fingerprint, source, location, subject, issuer,
                            not_before, not_after, sans_json, first_seen, last_seen)
                           VALUES (:fingerprint, :source, :location, :subject, :issuer,
                                   :not_before, :not_after, :sans_json, :ts, :ts)
                        """,
                        data,
                    )
                count += 1
        return count

    def list(
        self,
        source: Optional[str] = None,
        expiring_within_days: Optional[int] = None,
    ) -> list[Dict[str, Any]]:
        q = "SELECT * FROM cert_inventory"
        clauses = []
        params: dict[str, Any] = {}

        if source:
            clauses.append("source = :source")
            params["source"] = source

        if expiring_within_days is not None:
            # Compare ISO strings lexicographically works for ISO 8601 UTC,
            # but we can parse to datetime in Python after fetch for filtering too.
            # For portability, filter in Python:
            pass

        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY not_after ASC"

        rows = [dict(r) for r in self._conn.execute(q, params).fetchall()]

        # Optional in-Python filter for expiring_within_days
        if expiring_within_days is not None:
            now = datetime.now(timezone.utc)
            keep = []
            for r in rows:
                try:
                    exp = datetime.fromisoformat(r["not_after"])
                except Exception:
                    continue
                delta_days = int((exp - now).total_seconds() // 86400)
                if delta_days <= expiring_within_days:
                    r["days_left"] = delta_days
                    keep.append(r)
            rows = keep

        # Decode SANs
        for r in rows:
            try:
                r["sans"] = json.loads(r.get("sans_json") or "[]")
            except Exception:
                r["sans"] = []
        return rows

    def purge(self, source: Optional[str] = None) -> int:
        with self._conn:
            if source:
                cur = self._conn.execute("DELETE FROM cert_inventory WHERE source = ?", (source,))
            else:
                cur = self._conn.execute("DELETE FROM cert_inventory")
            return cur.rowcount