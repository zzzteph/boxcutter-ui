"""Best-effort outbound notifications on scan-done and new-critical. Fire-and-forget in a daemon thread so a
slow or dead endpoint never blocks the request that triggered it. Stdlib only (no extra deps).

Configure via env: NOTIFY_WEBHOOK (any URL that accepts a JSON POST), and/or TELEGRAM_BOT_TOKEN +
TELEGRAM_CHAT_ID. If nothing is configured, notify() is a no-op."""
from __future__ import annotations

import json
import threading
import urllib.request

from .config import settings


def _post(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8).read()
    except Exception:  # noqa: BLE001 - notifications are best-effort; never raise into the caller
        pass


def _telegram(text: str) -> None:
    if settings.telegram_bot_token and settings.telegram_chat_id:
        _post(f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
              {"chat_id": settings.telegram_chat_id, "text": text})


def _enabled() -> bool:
    return bool(settings.notify_webhook or (settings.telegram_bot_token and settings.telegram_chat_id))


def notify(kind: str, data: dict, text: str) -> None:
    """kind is 'scan_done' or 'new_critical'. Dispatches to the webhook (JSON: {event, ...data}) and Telegram
    (as text), in the background."""
    if not _enabled():
        return

    def run():
        if settings.notify_webhook:
            _post(settings.notify_webhook, {"event": kind, **data})
        _telegram(text)

    threading.Thread(target=run, daemon=True).start()
