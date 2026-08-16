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


def test_run_job_idle_timeout_kills_and_keeps_partial_output():
    """A job that prints something then hangs SILENT is killed on the idle timeout — but whatever it already
    printed is still captured and returned, because you must always be able to see the output it produced."""
    import sys
    import time as _t
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup._emit = lambda *a, **k: None
    sup.MOCK = False
    sup.JOB_IDLE_TIMEOUT = 1
    sup.JOB_MAX_RUNTIME = 0
    sup.JOB_TIMEOUT = 0
    sup.BOXCUTTER_CMD = [sys.executable, "-c",
                         "import time,sys; print('partial-line'); sys.stdout.flush(); time.sleep(30)"]
    t0 = _t.time()
    out = sup.run_job({"id": 1, "argv": [], "target": "x"}, {})
    assert _t.time() - t0 < 15                       # killed promptly on idle, not after 30s
    assert out["error"] and "idle" in out["error"]
    assert out["report"] and "partial-line" in out["report"]   # partial output preserved through the kill


def test_run_job_hard_cap_kills_chatty_runaway():
    """A job that keeps chattering forever never trips the idle clock, so the absolute JOB_MAX_RUNTIME backstop
    must still bound it — a runaway can't wedge a worker slot indefinitely."""
    import sys
    import time as _t
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup._emit = lambda *a, **k: None
    sup.MOCK = False
    sup.JOB_IDLE_TIMEOUT = 0                          # disable the idle path; exercise the absolute cap
    sup.JOB_MAX_RUNTIME = 1
    sup.JOB_TIMEOUT = 0
    sup.BOXCUTTER_CMD = [sys.executable, "-c",
                         "import time,sys\nwhile True:\n sys.stderr.write('tick\\n'); sys.stderr.flush(); time.sleep(0.1)"]
    t0 = _t.time()
    out = sup.run_job({"id": 1, "argv": [], "target": "x"}, {})
    assert _t.time() - t0 < 15
    assert out["error"] and "runtime" in out["error"]


def test_run_job_missing_engine_is_reported_not_crashed():
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup.MOCK = False
    sup.BOXCUTTER_CMD = ["definitely-not-a-real-binary-xyz-123"]
    out = sup.run_job({"id": 1, "argv": [], "target": "x"}, {})
    assert out["error"] and "not found" in out["error"]


def test_run_job_emits_lifecycle_steps():
    """Tools print their JSON to stdout and are silent on stderr, so run_job must still emit a start + finish
    step — otherwise the 'Live steps' view stays empty ('no steps yet')."""
    import sys
    sup = _load_supervisor()
    emitted = []
    sup._emit = lambda job_id, line, **k: emitted.append(line)
    sup.MOCK = False
    sup.BOXCUTTER_CMD = [sys.executable, "-c", "print('{\"success\": true, \"data\": [{}, {}]}')"]
    out = sup.run_job({"id": 1, "argv": ["httpx", "example.com"], "target": "example.com"}, {})
    assert out["error"] is None
    assert any(line.startswith("$ boxcutter httpx example.com") for line in emitted)   # start
    assert any("finished — 2 result item(s)" in line for line in emitted)          # finish w/ count
    # the raw engine stdout is kept for the debug view even though it parsed as a findings envelope
    assert out["report"] and '"data"' in out["report"]


def test_run_job_cancelled_by_server_kills_and_flags():
    """When the server puts a running job's id in CANCEL (scan deleted/stopped), run_job kills the subprocess
    promptly, flags the result as cancelled, and does NOT report it as finished — the worker then posts nothing
    so a reused id can't be polluted."""
    import sys
    import threading
    import time as _t
    sup = _load_supervisor()
    sup._req = lambda *a, **k: {}
    sup._emit = lambda *a, **k: None
    sup.MOCK = False
    sup.JOB_IDLE_TIMEOUT = 0
    sup.JOB_MAX_RUNTIME = 0
    sup.JOB_TIMEOUT = 0
    sup.BOXCUTTER_CMD = [sys.executable, "-c", "import time; time.sleep(30)"]

    def _cancel_soon():
        _t.sleep(1.0)
        with sup._LOCK:
            sup.CANCEL.add(999)

    threading.Thread(target=_cancel_soon, daemon=True).start()
    t0 = _t.time()
    out = sup.run_job({"id": 999, "argv": [], "target": "x"}, {})
    assert _t.time() - t0 < 15                        # killed promptly on cancel, not after 30s
    assert out.get("cancelled") is True
    assert out["error"] == "cancelled by server"


def test_agent_enroll_marks_internal():
    """The built-in agent (RUNNER_INTERNAL) must send internal=true on enroll so the server keeps it as the
    permanent singleton it won't let you delete."""
    sup = _load_supervisor()
    captured = {}

    def fake_req(method, path, body=None, *a, **k):
        captured["path"], captured["body"] = path, body
        return {"runner_token": "t", "runner_id": 1}

    sup._req = fake_req
    sup.CFG.update({"internal": True, "enroll_token": "x", "token": ""})
    sup.STATE["connected"] = False
    assert sup._enroll_locked() is True
    assert captured["path"] == "/runner/enroll"
    assert captured["body"].get("internal") is True


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
