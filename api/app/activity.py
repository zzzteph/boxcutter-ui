"""Activity feed: a clickable log of everything that happens (scan lifecycle, scanner claims, failures, …).
Best-effort — recording activity must never break the action that triggered it."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlmodel import Session

from .models import Activity, JobEvent


def log_activity(session: Session, kind: str, message: str, scan_id: int | None = None,
                 runner_id: int | None = None, severity: str = "info") -> None:
    try:
        session.add(Activity(kind=kind, message=message[:400], scan_id=scan_id,
                             runner_id=runner_id, severity=severity))
        session.commit()
    except Exception:  # noqa: BLE001 - never let logging break the caller
        session.rollback()


def prune_logs(session: Session, days: int) -> int:
    """Delete Activity + JobEvent rows older than `days` (both `at` columns are indexed), so these append-only
    log tables can't grow without bound. Set-based DELETE; a no-op when days <= 0. Returns rows removed."""
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        r1 = session.execute(delete(Activity).where(Activity.at < cutoff))
        r2 = session.execute(delete(JobEvent).where(JobEvent.at < cutoff))
        session.commit()
        return (r1.rowcount or 0) + (r2.rowcount or 0)
    except Exception:  # noqa: BLE001 - pruning must never break the sweeper
        session.rollback()
        return 0
