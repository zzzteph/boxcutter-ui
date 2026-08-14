"""Offline test harness. Configures a throwaway SQLite DB *before* importing the app (the engine is built at
import time from settings), then drives the real FastAPI app in-process. A 'runner' here is just a sequence of
HTTP calls to the same endpoints the real supervisor uses - so the pipe, the claim, and the diff are exercised
without the boxcutter engine and without scanning anything."""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore")

_TMP = pathlib.Path(tempfile.mkdtemp(prefix="bcui-test-"))
os.environ["DATABASE_URL"] = "sqlite:///" + (_TMP / "test.db").as_posix()
os.environ["SECRET_KEY"] = "test-secret-key-at-least-thirty-two-bytes-long"
os.environ["ADMIN_USER"] = "root"
os.environ["ADMIN_PASSWORD"] = "root"
os.environ["ENROLL_TOKEN"] = "test-enroll"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # put api/ on the path

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:   # context-manager form runs the lifespan (init_db + seed)
        yield c


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def login(client, username: str = "root", password: str = "root") -> str:
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


class FakeRunner:
    """A test double for the runner: enroll once, then claim/emit/result against the live app."""

    def __init__(self, client, enroll_token: str = "test-enroll", name: str = "pytest-runner"):
        self.client = client
        r = client.post("/runner/enroll", json={"token": enroll_token, "name": name, "slots": 1})
        assert r.status_code == 200, r.text
        self.id = r.json()["runner_id"]
        self.h = auth(r.json()["runner_token"])

    def heartbeat(self, busy=None):
        busy = busy or []
        return self.client.post("/runner/heartbeat", json={
            "status": "busy" if busy else "idle", "slots": 1, "busy_slots": len(busy),
            "current_jobs": busy, "version": "test"}, headers=self.h)

    def claim(self):
        self.heartbeat()
        r = self.client.post("/runner/claim", json={}, headers=self.h)
        assert r.status_code == 200, r.text
        return r.json()

    def emit(self, job_id, line, agent="", phase=""):
        return self.client.post(f"/runner/jobs/{job_id}/event",
                                json={"line": line, "agent": agent, "phase": phase}, headers=self.h)

    def result(self, job_id, data=None, report=None, error=None):
        return self.client.post(f"/runner/jobs/{job_id}/result",
                                json={"envelope": {"data": data or []}, "report": report, "error": error},
                                headers=self.h)

    def run_one(self, findings):
        """Claim the next job, emit a line, post `findings`. Returns the claimed job (or None)."""
        job = self.claim().get("job")
        if not job:
            return None
        self.emit(job["id"], f"scanning {job['target']}", agent=job["argv"][0])
        self.result(job["id"], data=findings)
        return job

    def drain(self, findings_for):
        """Run every currently-pending job for a scan; `findings_for(target)` supplies each job's findings."""
        ran = 0
        while True:
            job = self.claim().get("job")
            if not job:
                break
            self.emit(job["id"], f"scanning {job['target']}", agent=job["argv"][0])
            self.result(job["id"], data=findings_for(job["target"]))
            ran += 1
        return ran
