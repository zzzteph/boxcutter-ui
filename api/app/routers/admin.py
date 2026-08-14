"""User administration and LLM profiles. LLM api keys are write-only: created here, delivered only to a runner
at job time, and never returned to any client."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from ..db import get_session
from ..models import LLMProfile, User
from ..security import current_user, hash_password, require_admin

router = APIRouter(tags=["admin"])


class UserIn(BaseModel):
    username: str
    password: str
    role: str = "user"


class UserPatch(BaseModel):
    role: str | None = None
    password: str | None = None


@router.get("/users")
def list_users(admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    return [{"id": u.id, "username": u.username, "role": u.role,
             "must_change_password": u.must_change_password} for u in session.exec(select(User)).all()]


@router.post("/users")
def create_user(body: UserIn, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == body.username)).first():
        raise HTTPException(400, "username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    session.add(u)
    session.commit()
    session.refresh(u)
    return {"id": u.id, "username": u.username, "role": u.role}


@router.patch("/users/{uid}")
def patch_user(uid: int, body: UserPatch, admin: User = Depends(require_admin),
               session: Session = Depends(get_session)):
    u = session.get(User, uid)
    if not u:
        raise HTTPException(404)
    if body.role:
        u.role = body.role
    if body.password:
        u.password_hash = hash_password(body.password)
        u.must_change_password = True
    session.add(u)
    session.commit()
    return {"ok": True}


@router.delete("/users/{uid}")
def delete_user(uid: int, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    u = session.get(User, uid)
    if u:
        session.delete(u)
        session.commit()
    return {"ok": True}


# ---- LLM profiles -------------------------------------------------------------------------------------------
class LLMIn(BaseModel):
    name: str
    provider: str
    model: str | None = None
    proxy_url: str | None = None
    api_key: str | None = None


@router.get("/llm-profiles")
def list_llm(user: User = Depends(current_user), session: Session = Depends(get_session)):
    # any user may LIST profiles (to pick one for an ai_agent template); keys are never included
    return [{"id": p.id, "name": p.name, "provider": p.provider, "model": p.model,
             "proxy_url": p.proxy_url, "has_key": bool(p.api_key_secret)}
            for p in session.exec(select(LLMProfile)).all()]


@router.post("/llm-profiles")
def create_llm(body: LLMIn, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    p = LLMProfile(name=body.name, provider=body.provider, model=body.model, proxy_url=body.proxy_url,
                   api_key_secret=body.api_key or "", created_by=admin.id)
    session.add(p)
    session.commit()
    session.refresh(p)
    return {"id": p.id, "name": p.name}


class LLMPatch(BaseModel):
    model: str | None = None
    proxy_url: str | None = None
    api_key: str | None = None


@router.patch("/llm-profiles/{pid}")
def update_llm(pid: int, body: LLMPatch, admin: User = Depends(require_admin),
               session: Session = Depends(get_session)):
    p = session.get(LLMProfile, pid)
    if not p:
        raise HTTPException(404)
    if body.model is not None:
        p.model = body.model
    if body.proxy_url is not None:
        p.proxy_url = body.proxy_url
    if body.api_key:                      # only overwrite the key when a new one is supplied
        p.api_key_secret = body.api_key
    session.add(p)
    session.commit()
    return {"id": p.id, "name": p.name, "has_key": bool(p.api_key_secret)}


@router.delete("/llm-profiles/{pid}")
def delete_llm(pid: int, admin: User = Depends(require_admin), session: Session = Depends(get_session)):
    p = session.get(LLMProfile, pid)
    if p:
        session.delete(p)
        session.commit()
    return {"ok": True}
