"""First-boot seed: the admin user (root/root, must change password), the dev enroll token, a demo LLM
profile, and a starter set of templates (workflows, tools, agents) so the app is usable out of the box.

Everything here is idempotent - re-running skips anything that already exists by name."""
from __future__ import annotations

import json

from sqlmodel import Session, select

from .config import settings
from .db import engine
from .models import EnrollToken, LLMProfile, NotifySettings, Template, User
from .security import hash_password, hash_token

# Starter templates. Workflows/tools are the stock boxcutter names; extend these lists to add more.
WORKFLOWS = ["web-full", "recon"]
TOOLS = ["httpx", "nuclei", "sqlmap", "fuzz"]
AGENTS = ["irvin", "bob", "travis", "caleb"]
DEMO_PROFILE = "demo (set an API key)"


def _ensure_template(s: Session, name: str, kind: str, spec_name: str, owner_id: int,
                     llm_profile_id: int | None = None, context: str | None = None) -> None:
    if s.exec(select(Template).where(Template.name == name)).first():
        return
    s.add(Template(name=name, kind=kind, spec_json=json.dumps({"name": spec_name, "flags": []}),
                   context=context, llm_profile_id=llm_profile_id, owner_id=owner_id))


def seed() -> None:
    with Session(engine) as s:
        admin = s.exec(select(User).where(User.username == settings.admin_user)).first()
        if not admin:
            admin = User(username=settings.admin_user, password_hash=hash_password(settings.admin_password),
                         role="admin", must_change_password=True)
            s.add(admin)
            s.commit()
            s.refresh(admin)

        if settings.enroll_token:
            th = hash_token(settings.enroll_token)
            if not s.exec(select(EnrollToken).where(EnrollToken.token_hash == th)).first():
                s.add(EnrollToken(token_hash=th, label="seed (from .env)"))

        # a placeholder LLM profile so the agent templates are visible; set a real key to run them for real
        profile = s.exec(select(LLMProfile).where(LLMProfile.name == DEMO_PROFILE)).first()
        if not profile:
            profile = LLMProfile(name=DEMO_PROFILE, provider="anthropic", model="claude-sonnet-5",
                                 api_key_secret="", created_by=admin.id)
            s.add(profile)
            s.commit()
            s.refresh(profile)

        for w in WORKFLOWS:
            _ensure_template(s, w, "workflow", w, admin.id)
        for t in TOOLS:
            _ensure_template(s, t, "tool", t, admin.id)
        for a in AGENTS:
            _ensure_template(s, a, "ai_agent", a, admin.id, llm_profile_id=profile.id,
                             context="Authorized assessment. Report only real, exploitable issues.")

        # Telegram notification settings singleton — seed from env if a bot token/chat id were provided
        if not s.exec(select(NotifySettings)).first():
            ns = NotifySettings(id=1)
            if settings.telegram_bot_token and settings.telegram_chat_id:
                ns.telegram_enabled = True
                ns.telegram_token = settings.telegram_bot_token
                ns.telegram_chat_id = settings.telegram_chat_id
            s.add(ns)
        s.commit()
