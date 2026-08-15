"""The runner supervisor's MOCK_RUNNER path returns a well-formed envelope with no engine and no network."""
from __future__ import annotations

import importlib.util
import pathlib


def _load_supervisor():
    path = pathlib.Path(__file__).resolve().parents[2] / "runner" / "supervisor.py"
    spec = importlib.util.spec_from_file_location("supervisor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mock_run_envelope():
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}          # neutralize event posting (no server in this test)
    out = sup._mock_run({"id": 1, "argv": ["httpx", "example.com"], "target": "example.com"})
    assert out["error"] is None
    assert "boxcutter httpx example.com" in out["report"]     # raw stdout for the debug view
    data = out["envelope"]["data"]
    assert out["envelope"]["success"] is True
    titles = {d["title"] for d in data}
    assert "Missing security headers" in titles          # a realistic issue (kept)
    assert any("reachable" in t.lower() for t in titles)  # a recon line (server-side is_issue drops it)
    assert all(d["url"] == "http://example.com" for d in data)


def test_scrub_redacts_secrets():
    sup = _load_supervisor()
    out = sup._scrub("Authorization: Bearer sk-super-secret-123 done", ["sk-super-secret-123"])
    assert "sk-super-secret-123" not in out and "***" in out


def test_run_job_times_out_and_is_killed():
    """A hung engine must not wedge a slot: run_job bounds it by JOB_TIMEOUT and kills the process tree."""
    import sys
    import time as _t
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup.MOCK = False
    sup.JOB_TIMEOUT = 1
    sup.BOXCUTTER_CMD = [sys.executable, "-c", "import time; time.sleep(30)"]
    t0 = _t.time()
    out = sup.run_job({"id": 1, "argv": [], "target": "x"}, {})
    assert _t.time() - t0 < 15                       # killed promptly, not after 30s
    assert out["error"] and "timed out" in out["error"]


def test_run_job_missing_engine_is_reported_not_crashed():
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup.MOCK = False
    sup.BOXCUTTER_CMD = ["definitely-not-a-real-binary-xyz-123"]
    out = sup.run_job({"id": 1, "argv": [], "target": "x"}, {})
    assert out["error"] and "not found" in out["error"]


def test_agent_login_is_local_and_settable():
    """The agent UI login is self-contained (root + a settable local password) and never delegates to the
    server — so a scanner stays manageable regardless of the server's credentials/state."""
    sup = _load_supervisor()
    assert sup._validate_login("root", "root") is True          # default
    assert sup._validate_login("root", "nope") is False
    assert sup._validate_login("admin", "root") is False        # only 'root' locally
    sup.CFG["ui_password_hash"] = sup._hash_pw("s3cret!")        # set a password -> default stops working
    assert sup._validate_login("root", "root") is False
    assert sup._validate_login("root", "s3cret!") is True
    sup.CFG["server_url"] = "http://example.com:8000"            # a configured server must NOT change the login
    assert sup._validate_login("root", "s3cret!") is True
    assert sup._validate_login("root", "server-only-cred") is False
