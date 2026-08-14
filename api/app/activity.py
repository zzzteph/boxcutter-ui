"""Activity feed: a clickable log of everything that happens (scan lifecycle, scanner claims, failures, …).
Best-effort — recording activity must never break the action that triggered it."""
from __future__ import annotations

from sqlmodel import Session

from .models import Activity


def log_activity(session: Session, kind: str, message: str, scan_id: int | None = None,
                 runner_id: int | None = None, severity: str = "info") -> None:
    try:
        session.add(Activity(kind=kind, message=message[:400], scan_id=scan_id,
                             runner_id=runner_id, severity=severity))
        session.commit()
    except Exception:  # noqa: BLE001 - never let logging break the caller
        session.rollback()
