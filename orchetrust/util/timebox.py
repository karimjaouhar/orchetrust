from __future__ import annotations
from datetime import datetime, timezone

def iso_to_days_left(iso_dt: str | None) -> int | None:
    if not iso_dt:
        return None
    try:
        exp = datetime.fromisoformat(iso_dt)
        now = datetime.now(timezone.utc)
        return int((exp - now).total_seconds() // 86400)
    except Exception:
        return None