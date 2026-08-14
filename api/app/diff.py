"""Findings normalization, fingerprinting, and the rescan reconcile (auto states: new / open / resolved)."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlmodel import Session, select

from .models import Finding, FindingEvent

# Informational reconnaissance / reachability items (e.g. "host reachable") are not issues and must not render
# as findings.
_NON_ISSUE_TITLE = re.compile(
    r"\b(reachable|is up|is alive|host up|alive|resolved to|responded|open port|"
    r"no (issues|findings|vulnerabilit))\b", re.I)
_RECON_CLS = {"recon", "reachable", "up", "alive", "info", "dns", "portscan", "port", "ping"}


def is_issue(f: dict) -> bool:
    """True if an engine-envelope item is a real finding worth surfacing; False for pure recon/reachability
    signals. Anything with a genuine severity and a non-recon class is kept."""
    title = str(f.get("title", ""))
    if _NON_ISSUE_TITLE.search(title):
        return False
    sev = str(f.get("severity", "")).strip().lower()
    cls = str(f.get("cls", "")).strip().lower()
    if sev in ("", "info", "informational", "none") and cls in _RECON_CLS:
        return False
    return True


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite hands datetimes back naive; treat stored times as UTC so comparisons are safe."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_url(u: str) -> str:
    try:
        p = urlsplit(u or "")
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), (p.path.rstrip("/") or "/"), "", ""))
    except Exception:  # noqa: BLE001
        return u or ""


def fingerprint(target: str, kind: str, cls: str, severity: str, url: str, title: str) -> str:
    raw = "|".join([target or "", kind or "", (cls or "").lower(), (severity or "").lower(),
                    normalize_url(url), (title or "").strip().lower()])
    return hashlib.sha256(raw.encode()).hexdigest()


def upsert_finding(session: Session, scan_id: int, kind: str, target: str, f: dict,
                   run_no: int = 0) -> tuple[str, bool]:
    """Insert or refresh a finding from one engine-envelope item; returns (fingerprint, created). A resolved
    finding that shows up again flips back to open (a 'reopened' event). A brand-new fingerprint gets a 'new'
    event. `last_seen` is bumped on every sighting - reconcile uses it to decide what this run saw."""
    fp = fingerprint(target, kind, f.get("cls", ""), f.get("severity", ""), f.get("url", ""), f.get("title", ""))
    now = datetime.now(timezone.utc)
    existing = session.exec(select(Finding).where(
        Finding.scan_id == scan_id, Finding.fingerprint == fp)).first()
    raw = json.dumps(f)[:8000]                # keep the full item boxcutter reported, for the detail view
    if existing:
        existing.last_seen = now
        existing.raw_json = raw
        if existing.state == "resolved":
            existing.state = "open"
            session.add(FindingEvent(scan_id=scan_id, finding_id=existing.id, run_no=run_no, kind="reopened"))
        session.add(existing)
        session.commit()
        return fp, False
    else:
        finding = Finding(
            scan_id=scan_id, target=target, fingerprint=fp, template_kind=kind,
            severity=str(f.get("severity", "info")).title(), title=str(f.get("title", ""))[:300],
            url=f.get("url", ""),
            evidence=str(f.get("evidence", ""))[:2000], reproduce=str(f.get("reproduce", ""))[:2000],
            raw_json=raw, state="new", first_seen=now, last_seen=now)
        finding.cls = str(f.get("cls", "")).lower()   # 'cls' can't be a constructor kwarg (shadows __new__)
        session.add(finding)
        session.commit()
        session.refresh(finding)
        session.add(FindingEvent(scan_id=scan_id, finding_id=finding.id, run_no=run_no, kind="new"))
        session.commit()
        return fp, True


def reconcile_run(session: Session, scan_id: int, run_no: int, cutoff: datetime | None) -> dict:
    """Reconcile a scan's findings after a run whose jobs started at `cutoff` (the scan's last_run_at).

    - seen this run (last_seen >= cutoff), first appeared this run (first_seen >= cutoff) -> ``new``
    - seen this run, but first seen in an earlier run                                     -> ``open``
    - not seen this run                                                                   -> ``resolved``

    A FindingEvent is written for every actual state change. Returns a {new, open, resolved} tally.
    """
    cutoff = _aware(cutoff)
    stats = {"new": 0, "open": 0, "resolved": 0}
    for f in session.exec(select(Finding).where(Finding.scan_id == scan_id)).all():
        last_seen = _aware(f.last_seen)
        first_seen = _aware(f.first_seen)
        seen = last_seen is not None and (cutoff is None or last_seen >= cutoff)
        if seen:
            is_new = cutoff is not None and first_seen is not None and first_seen >= cutoff
            new_state = "new" if is_new else "open"
            if f.state != new_state:
                # new -> open is the normal "carried over" transition; anything -> open after being
                # resolved was already flagged 'reopened' at upsert time.
                if new_state == "open" and f.state == "new":
                    session.add(FindingEvent(scan_id=scan_id, finding_id=f.id, run_no=run_no, kind="still_open"))
                f.state = new_state
                session.add(f)
            stats[new_state] += 1
        else:
            if f.state != "resolved":
                f.state = "resolved"
                session.add(f)
                session.add(FindingEvent(scan_id=scan_id, finding_id=f.id, run_no=run_no, kind="resolved"))
            stats["resolved"] += 1
    session.commit()
    return stats
