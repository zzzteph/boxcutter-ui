"""End-to-end acceptance for phases 1-3, driven offline against the real app.

Covers: the walking-skeleton pipe (login -> template -> scan -> claim -> event -> result -> findings),
the authorized-targets gate, ai_agent secret delivery (and the no-secret-to-the-browser rule), user admin,
scan lifecycle (pause stops dispatch, stop cancels), sharing (read vs write), and the rescan diff."""
from __future__ import annotations

from conftest import FakeRunner, auth, login


# ---- phase 1: the pipe end to end --------------------------------------------------------------------------
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


def _tool_template(client, h, name="httpx probe", tool="httpx", flags=None):
    r = client.post("/templates", json={"name": name, "kind": "tool",
                                        "spec": {"name": tool, "flags": flags or []}}, headers=h)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_full_pipe(client):
    h = auth(login(client))
    tid = _tool_template(client, h)
    r = client.post("/scans", json={"name": "skeleton", "template_id": tid,
                                    "targets": ["example.com"], "authorized": True}, headers=h)
    assert r.status_code == 200, r.text
    sid, jobs = r.json()["id"], r.json()["jobs"]
    assert jobs == 1

    runner = FakeRunner(client)
    claimed = runner.claim()["job"]
    assert claimed and claimed["target"] == "example.com"
    assert claimed["argv"][:2] == ["httpx", "example.com"]
    runner.emit(claimed["id"], "probing example.com", agent="httpx")
    runner.result(claimed["id"], data=[{"severity": "medium", "title": "Missing HSTS",
                                        "url": "http://example.com", "cls": "header",
                                        "evidence": "no Strict-Transport-Security"}])

    findings = client.get(f"/scans/{sid}/findings", headers=h).json()["items"]
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing HSTS"
    assert findings[0]["severity"] == "Medium"        # normalized via .title()
    assert findings[0]["state"] == "new"

    events = client.get(f"/scans/{sid}/events?since=0", headers=h).json()
    assert any("probing example.com" in e["line"] for e in events)

    assert client.get(f"/scans/{sid}", headers=h).json()["status"] == "done"


def test_scan_create_needs_no_ack(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="no-ack")
    r = client.post("/scans", json={"name": "x", "template_id": tid, "targets": ["example.com"]}, headers=h)
    assert r.status_code == 200 and r.json()["jobs"] == 1     # no authorization acknowledgment required
    client.post(f"/scans/{r.json()['id']}/stop", headers=h)  # don't leave a pending job for the shared queue


# ---- phase 2: ai_agent + secrets, users, lifecycle, sharing ------------------------------------------------
def test_ai_agent_secret_delivery_and_no_leak(client):
    h = auth(login(client))
    r = client.post("/llm-profiles", json={"name": "claude-main", "provider": "anthropic",
                                           "model": "claude-x", "api_key": "sk-super-secret"}, headers=h)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]

    # the key is never returned by the list endpoint (only has_key)
    profiles = client.get("/llm-profiles", headers=h).json()
    prof = next(p for p in profiles if p["id"] == pid)
    assert prof["has_key"] is True
    assert "api_key" not in prof and "api_key_secret" not in prof
    assert "sk-super-secret" not in str(profiles)

    r = client.post("/templates", json={"name": "irvin-agent", "kind": "ai_agent",
                                        "spec": {"name": "irvin", "flags": ["--depth", "2"]},
                                        "context": "focus on auth", "llm_profile_id": pid}, headers=h)
    tid = r.json()["id"]
    sid = client.post("/scans", json={"name": "agent-scan", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]

    runner = FakeRunner(client, name="agent-runner")
    res = runner.claim()
    job = res["job"]
    argv = job["argv"]
    assert argv[:3] == ["ai", "irvin", "example.com"]         # `boxcutter ai <agent> <target>`
    assert "--provider" in argv and argv[argv.index("--provider") + 1] == "anthropic"
    assert "--model" in argv and argv[argv.index("--model") + 1] == "claude-x"
    assert "--context" in argv and argv[argv.index("--context") + 1] == "focus on auth"
    assert argv[-2:] == ["--depth", "2"]                      # template flags appended
    # the secret is delivered only in the secrets channel, never inside argv
    assert res["secrets"] == {"ANTHROPIC_API_KEY": "sk-super-secret"}
    assert "sk-super-secret" not in " ".join(argv)
    _ = sid


def test_single_group_all_visible_and_actionable(client):
    # no per-user sharing: every authenticated user sees all scans/templates and can act on them
    h = auth(login(client))
    client.post("/users", json={"username": "carol", "password": "carolpass", "role": "user"}, headers=h)
    tid = _tool_template(client, h, name="group-t")
    sid = client.post("/scans", json={"name": "group-scan", "template_id": tid,
                                      "targets": ["g.example.com"], "authorized": True}, headers=h).json()["id"]
    ch = auth(login(client, "carol", "carolpass"))
    assert any(s["id"] == sid for s in client.get("/scans", headers=ch).json()["items"])   # visible, unshared
    assert any(t["id"] == tid for t in client.get("/templates", headers=ch).json())
    assert client.post(f"/scans/{sid}/pause", headers=ch).status_code == 200          # and actionable


def test_user_admin_and_role_gate(client):
    h = auth(login(client))
    r = client.post("/users", json={"username": "alice", "password": "wonderland", "role": "user"}, headers=h)
    assert r.status_code == 200, r.text
    users = client.get("/users", headers=h).json()
    assert any(u["username"] == "alice" for u in users)
    # a normal user cannot list users
    ah = auth(login(client, "alice", "wonderland"))
    assert client.get("/users", headers=ah).status_code == 403


def test_pause_stops_dispatch_then_resume(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="pause-t")
    sid = client.post("/scans", json={"name": "pausable", "template_id": tid,
                                      "targets": ["a.example.com", "b.example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="pause-runner")
    # take one job, leave one pending
    first = runner.run_one([])
    assert first is not None
    client.post(f"/scans/{sid}/pause", headers=h)
    assert runner.claim()["job"] is None                     # paused -> nothing dispatches
    client.post(f"/scans/{sid}/resume", headers=h)
    assert runner.claim()["job"] is not None                 # resumed -> the pending job dispatches


def test_stop_cancels_pending(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="stop-t")
    sid = client.post("/scans", json={"name": "stoppable", "template_id": tid,
                                      "targets": ["c.example.com", "d.example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    client.post(f"/scans/{sid}/stop", headers=h)
    runner = FakeRunner(client, name="stop-runner")
    assert runner.claim()["job"] is None
    jobs = client.get(f"/scans/{sid}", headers=h).json()["jobs"]
    assert jobs.get("cancelled", 0) == 2


# ---- phase 4: SSE live log ----------------------------------------------------------------------------------
def test_sse_stream_pushes_events(client):
    tok = login(client)
    h = auth(tok)
    tid = _tool_template(client, h, name="sse-t")
    sid = client.post("/scans", json={"name": "sse", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="sse-runner")
    job = runner.claim()["job"]
    runner.emit(job["id"], "hello-sse-line", agent="httpx", phase="scan")
    runner.result(job["id"], data=[])

    # Drive the SSE generator directly (an infinite stream + TestClient's portal would hang on teardown).
    import asyncio
    from app.routers.scans import sse_event_gen

    async def drive():
        gen = sse_event_gen(sid, 0)
        try:
            async for chunk in gen:
                if chunk.startswith("data:") and "hello-sse-line" in chunk:
                    return True
        finally:
            await gen.aclose()
        return False

    assert asyncio.run(asyncio.wait_for(drive(), timeout=8))


def test_sse_requires_auth(client):
    # auth is checked before the scan lookup, so a bogus id still 401s with no token (and leaves no job behind)
    with client.stream("GET", "/scans/999999/stream?since=0") as r:
        assert r.status_code == 401


# ---- phase 3: the rescan diff -------------------------------------------------------------------------------
def test_rescan_diff_new_open_resolved(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="diff-t", tool="nuclei")
    sid = client.post("/scans", json={"name": "diffed", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]

    A = {"severity": "high", "title": "A", "url": "http://example.com/a", "cls": "x"}
    B = {"severity": "low", "title": "B", "url": "http://example.com/b", "cls": "y"}
    C = {"severity": "medium", "title": "C", "url": "http://example.com/c", "cls": "z"}

    runner = FakeRunner(client, name="diff-runner")
    # run 1: A + B  -> both new
    assert runner.drain(lambda t: [A, B]) == 1
    f1 = {x["title"]: x for x in client.get(f"/scans/{sid}/findings", headers=h).json()["items"]}
    assert f1["A"]["state"] == "new" and f1["B"]["state"] == "new"
    assert client.get(f"/scans/{sid}", headers=h).json()["status"] == "done"

    # rerun, run 2: B + C  (A dropped, C added)
    rr = client.post(f"/scans/{sid}/rerun", headers=h).json()
    assert rr["run_no"] == 2 and rr["jobs"] == 1
    assert runner.drain(lambda t: [B, C]) == 1

    f2 = {x["title"]: x for x in client.get(f"/scans/{sid}/findings", headers=h).json()["items"]}
    assert f2["A"]["state"] == "resolved"        # present run1, absent run2
    assert f2["B"]["state"] == "open"            # present both runs
    assert f2["C"]["state"] == "new"             # first seen run2

    # the default findings view hides resolved via the ?state filter, and the summary tallies match
    open_only = client.get(f"/scans/{sid}/findings?state=open", headers=h).json()["items"]
    assert {x["title"] for x in open_only} == {"B"}
    summ = next(s for s in client.get("/scans", headers=h).json()["items"] if s["id"] == sid)
    assert (summ["findings_new"], summ["findings_open_state"], summ["findings_resolved"]) == (1, 1, 1)


# ---- phase 5: report export + notifications -----------------------------------------------------------------
def test_report_export_markdown(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="report-t")
    sid = client.post("/scans", json={"name": "report-scan", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="report-runner")
    runner.run_one([{"severity": "critical", "title": "SQL injection", "url": "http://example.com/q",
                     "cls": "sqli", "evidence": "' OR 1=1", "reproduce": "curl ..."}])
    r = client.get(f"/scans/{sid}/report", headers=h)
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "")
    md = r.text
    assert "# Scan report — report-scan" in md
    assert "## Executive summary" in md and "1 critical" in md
    assert "[Critical] SQL injection" in md and "' OR 1=1" in md


def test_notifications_fire_on_done_and_critical(client, monkeypatch):
    import time
    from app import notify as notify_mod
    from app.config import settings

    captured = []
    monkeypatch.setattr(notify_mod, "_post", lambda url, payload: captured.append(payload))
    monkeypatch.setattr(settings, "notify_webhook", "http://capture.local/hook")

    h = auth(login(client))
    tid = _tool_template(client, h, name="notify-t")
    sid = client.post("/scans", json={"name": "notif-scan", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="notify-runner")
    runner.run_one([{"severity": "critical", "title": "RCE", "url": "http://example.com", "cls": "rce"}])

    end = time.time() + 3.0
    while time.time() < end and len({e["event"] for e in captured}) < 2:
        time.sleep(0.05)
    kinds = {e["event"] for e in captured}
    assert "new_critical" in kinds and "scan_done" in kinds
    done = next(e for e in captured if e["event"] == "scan_done")
    assert done["scan"] == "notif-scan" and done["new"] >= 1
    _ = sid


# ---- feedback round: preseed, single group, recon filter, duration/progress, runner detail -----------------
def test_preseed_templates_and_demo_profile(client):
    h = auth(login(client))
    tmpls = client.get("/templates", headers=h).json()
    assert any(t["kind"] == "workflow" and t["spec"]["name"] == "web-full" for t in tmpls)
    assert any(t["kind"] == "tool" and t["spec"]["name"] == "httpx" for t in tmpls)
    assert any(t["kind"] == "ai_agent" and t["spec"]["name"] == "irvin" for t in tmpls)
    assert any(p["name"].startswith("demo") for p in client.get("/llm-profiles", headers=h).json())
    # every seeded template carries the stock engine's own description, so the picker is self-explanatory
    # (seeded templates are named after the tool/workflow/agent; other tests add extra httpx-spec templates)
    seeded = {t["name"]: t for t in tmpls}
    assert "httpx" in seeded["httpx"]["description"].lower() and len(seeded["httpx"]["description"]) > 10
    assert seeded["web-full"]["description"].strip() and seeded["irvin"]["description"].strip()


def test_edit_template(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="editable")
    # rename, add a boxcutter parameter, and set a description via PATCH
    r = client.patch(f"/templates/{tid}", json={
        "name": "renamed", "description": "custom desc",
        "spec": {"name": "httpx", "params": [{"flag": "--rate", "value": "50"}]}}, headers=h)
    assert r.status_code == 200, r.text
    got = client.get(f"/templates/{tid}", headers=h).json()
    assert got["name"] == "renamed" and got["description"] == "custom desc"
    assert got["spec"]["params"] == [{"flag": "--rate", "value": "50"}]
    # the edited parameter flows into the next scan's argv
    sid = client.post("/scans", json={"name": "edited", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    claimed = FakeRunner(client, name="edit-runner").claim()["job"]
    assert claimed["argv"] == ["httpx", "example.com", "--rate", "50"]
    # a bad kind is rejected
    assert client.patch(f"/templates/{tid}", json={"kind": "nope"}, headers=h).status_code == 400


def test_stop_cancels_inflight_and_heartbeat_tells_agent(client):
    """Stopping a scan cancels its in-flight (claimed) job, the heartbeat then tells the holding agent to stop
    it, and the agent's late result for it is ignored (no finding leaks in)."""
    h = auth(login(client))
    tid = _tool_template(client, h, name="stopme")
    sid = client.post("/scans", json={"name": "stopme", "template_id": tid,
                                      "targets": ["a.example.com", "b.example.com"], "authorized": True},
                      headers=h).json()["id"]
    r = FakeRunner(client, name="stop-runner")
    job = r.claim()["job"]
    assert job and job["token"]
    assert client.post(f"/scans/{sid}/stop", headers=h).status_code == 200
    hb = r.heartbeat(busy=[job["id"]]).json()
    assert job["id"] in hb["cancel"]                 # server tells the agent to stop the job it's holding
    # a late result for the cancelled job is dropped — no "late" finding appears
    r.result(job["id"], data=[{"severity": "high", "cls": "x", "title": "late", "url": "http://a.example.com"}])
    findings = client.get(f"/scans/{sid}/findings", headers=h).json()["items"]
    assert not any(f["title"] == "late" for f in findings)


def test_deleted_scan_job_is_cancelled_and_stale_post_rejected(client):
    """After a scan is deleted its job rows are gone, so the heartbeat tells the agent to stop them and any
    late event/result for that (now free) id is rejected instead of landing on a reused id."""
    h = auth(login(client))
    tid = _tool_template(client, h, name="delme")
    sid = client.post("/scans", json={"name": "delme", "template_id": tid,
                                      "targets": ["c.example.com"], "authorized": True}, headers=h).json()["id"]
    r = FakeRunner(client, name="del-runner")
    job = r.claim()["job"]
    assert client.delete(f"/scans/{sid}", headers=h).status_code == 200
    hb = r.heartbeat(busy=[job["id"]]).json()
    assert job["id"] in hb["cancel"]                 # job row gone -> cancel
    assert r.emit(job["id"], "late line").status_code == 404


def test_result_token_guard_rejects_reused_id(client):
    """The run token is what makes id reuse safe: a post carrying a different token than the current job (as a
    stale agent finishing a deleted job whose integer id was reused) is rejected; the right token is accepted."""
    h = auth(login(client))
    tid = _tool_template(client, h, name="tok")
    sid = client.post("/scans", json={"name": "tok", "template_id": tid,
                                      "targets": ["d.example.com"], "authorized": True}, headers=h).json()["id"]
    r = FakeRunner(client, name="tok-runner")
    job = r.claim()["job"]
    assert job["token"] and len(job["token"]) == 32
    bad = client.post(f"/runner/jobs/{job['id']}/result",
                      json={"envelope": {"data": []}, "token": "deadbeef" * 4}, headers=r.h)
    assert bad.status_code == 404
    ok = client.post(f"/runner/jobs/{job['id']}/result",
                     json={"envelope": {"data": []}, "token": job["token"]}, headers=r.h)
    assert ok.status_code == 200


def test_reachable_recon_is_not_a_finding(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="recon-t")
    sid = client.post("/scans", json={"name": "recon", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    FakeRunner(client, name="recon-runner").run_one([
        {"severity": "info", "cls": "recon", "title": "example.com reachable", "url": "http://example.com"},
        {"severity": "low", "cls": "headers", "title": "Missing security headers", "url": "http://example.com"},
    ])
    titles = {f["title"] for f in client.get(f"/scans/{sid}/findings", headers=h).json()["items"]}
    assert "Missing security headers" in titles
    assert not any("reachable" in t.lower() for t in titles)


def test_scan_progress_and_duration(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="dur-t")
    sid = client.post("/scans", json={"name": "dur", "template_id": tid,
                                      "targets": ["a.example.com", "b.example.com"],
                                      "authorized": True}, headers=h).json()["id"]

    def summ():
        return next(s for s in client.get("/scans", headers=h).json()["items"] if s["id"] == sid)
    s0 = summ()
    assert s0["jobs_total"] == 2 and s0["jobs_done"] == 0 and s0["finished_at"] is None
    FakeRunner(client, name="dur-runner").drain(
        lambda t: [{"severity": "low", "title": "h", "url": "http://x", "cls": "headers"}])
    s1 = summ()
    assert s1["jobs_total"] == 2 and s1["jobs_done"] == 2
    assert s1["status"] == "done" and s1["finished_at"] is not None and s1["last_run_at"] is not None


def test_heartbeat_metrics_and_runner_detail(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="rd-t")
    sid = client.post("/scans", json={"name": "rd", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="rd-runner")
    client.post("/runner/heartbeat", json={"status": "idle", "slots": 2, "busy_slots": 0,
                                           "current_jobs": [], "metrics": {"cpu": 42.0, "mem": 51.0}},
                headers=runner.h)
    row = next(r for r in client.get("/runners", headers=h).json() if r["id"] == runner.id)
    assert row["metrics"] == {"cpu": 42.0, "mem": 51.0}

    runner.run_one([{"severity": "low", "title": "h", "url": "http://example.com", "cls": "headers"}])
    detail = client.get(f"/runners/{runner.id}", headers=h).json()
    assert "metrics" in detail and "current" in detail and "last_jobs" in detail
    assert any(j["target"] == "example.com" and j["status"] == "done" for j in detail["last_jobs"])
    _ = sid


def test_api_key_auth_and_revoke(client):
    h = auth(login(client))
    made = client.post("/api-keys", json={"name": "ci"}, headers=h).json()
    key = made["key"]
    assert key.startswith("bck_")
    lst = client.get("/api-keys", headers=h).json()
    assert lst and all("key" not in k for k in lst)                 # secret never listed
    assert any(k["prefix"].startswith("bck_") for k in lst)
    assert client.get("/scans", headers={"X-API-Key": key}).status_code == 200
    assert client.get("/scans", headers={"Authorization": "Bearer " + key}).status_code == 200
    client.delete(f"/api-keys/{made['id']}", headers=h)
    assert client.get("/scans", headers={"X-API-Key": key}).status_code == 401


def test_system_user_is_api_only(client):
    h = auth(login(client))
    r = client.post("/system-users", json={"username": "svc-bot"}, headers=h).json()
    assert r["role"] == "service" and r["key"].startswith("bck_")
    # a service account cannot get a UI token with a password
    assert client.post("/auth/login", json={"username": "svc-bot", "password": "x"}).status_code in (401, 403)
    # but its key drives the REST API
    assert client.get("/scans", headers={"X-API-Key": r["key"]}).status_code == 200
    assert any(u["username"] == "svc-bot" and u["role"] == "service"
               for u in client.get("/users", headers=h).json())


def test_runner_enroll_with_system_user_key(client):
    h = auth(login(client))
    key = client.post("/system-users", json={"username": "fleet-bot"}, headers=h).json()["key"]
    # a system-user API key can enroll a runner (wires enrollment to the system user), no enroll token needed
    r = client.post("/runner/enroll", json={"api_key": key, "name": "keyed-runner"})
    assert r.status_code == 200 and r.json()["runner_token"]
    assert client.post("/runner/enroll", json={"api_key": "bck_bogus"}).status_code == 401


def test_scan_jobs_debug_view(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="dbg-t")
    sid = client.post("/scans", json={"name": "dbg", "template_id": tid,
                                      "targets": ["example.com"], "authorized": True}, headers=h).json()["id"]
    runner = FakeRunner(client, name="dbg-runner")
    job = runner.claim()["job"]                 # argv is recorded at claim time
    runner.emit(job["id"], "scanning", agent="httpx")
    runner.result(job["id"], data=[{"severity": "low", "title": "h", "url": "http://example.com", "cls": "headers"}],
                  report="RAW ENGINE OUTPUT\nline 2")
    dbg = client.get(f"/scans/{sid}/jobs", headers=h).json()["items"]
    assert dbg and dbg[0]["command"] == "boxcutter httpx example.com"
    assert "RAW ENGINE OUTPUT" in dbg[0]["output"] and dbg[0]["status"] == "done"


def test_scan_asset_count(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="assets-t")
    sid = client.post("/scans", json={"name": "assets", "template_id": tid,
                                      "targets": ["a.com", "b.com", "c.com"], "authorized": True},
                      headers=h).json()["id"]
    s = next(x for x in client.get("/scans", headers=h).json()["items"] if x["id"] == sid)
    assert s["assets"] == 3


def test_fair_claim_spreads_across_scans(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="fair-runner")
    runner.drain(lambda t: [])                       # clear pending jobs left by earlier tests
    tid = _tool_template(client, h, name="fair-t")
    a = client.post("/scans", json={"name": "fairA", "template_id": tid, "targets": ["a1", "a2"],
                                    "authorized": True}, headers=h).json()["id"]
    b = client.post("/scans", json={"name": "fairB", "template_id": tid, "targets": ["b1", "b2"],
                                    "authorized": True}, headers=h).json()["id"]
    j1 = runner.claim()["job"]
    j2 = runner.claim()["job"]
    assert j1 and j2 and {j1["scan_id"], j2["scan_id"]} == {a, b}   # one from each scan, round-robin


def test_failed_job_retries_then_fails(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="retry-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="retry-t")
    sid = client.post("/scans", json={"name": "retry", "template_id": tid, "targets": ["r"],
                                      "authorized": True}, headers=h).json()["id"]
    statuses = []
    for _ in range(5):
        job = runner.claim().get("job")
        if not job:
            break
        runner.result(job["id"], error="boom")
        statuses.append(client.get(f"/scans/{sid}/jobs", headers=h).json()["items"][0]["status"])
    assert "pending" in statuses            # retried at least once
    row = client.get(f"/scans/{sid}/jobs", headers=h).json()["items"][0]
    assert row["status"] == "failed" and row["attempts"] == 3    # then failed at the cap


def test_findings_pagination_filter_sort(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="page-t")
    sid = client.post("/scans", json={"name": "page", "template_id": tid, "targets": ["example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    FakeRunner(client, name="page-runner").run_one([
        {"severity": "low", "title": "L", "url": "http://x/l", "cls": "c"},
        {"severity": "critical", "title": "C", "url": "http://x/c", "cls": "c"},
        {"severity": "medium", "title": "M", "url": "http://x/m", "cls": "c"},
    ])
    r = client.get(f"/scans/{sid}/findings", headers=h).json()
    assert r["total"] == 3 and r["items"][0]["severity"] == "Critical"        # severity sort
    p2 = client.get(f"/scans/{sid}/findings?limit=1&offset=1", headers=h).json()
    assert p2["total"] == 3 and len(p2["items"]) == 1 and p2["items"][0]["severity"] == "Medium"
    crit = client.get(f"/scans/{sid}/findings?severity=Critical", headers=h).json()
    assert crit["total"] == 1 and crit["items"][0]["title"] == "C"
    srch = client.get(f"/scans/{sid}/findings?q=/m", headers=h).json()
    assert any(f["title"] == "M" for f in srch["items"])


def test_findings_sort_by_column_and_raw_detail(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="sortcol-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="sortcol-t")
    sid = client.post("/scans", json={"name": "sortcol", "template_id": tid, "targets": ["example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    runner.run_one([
        {"severity": "low", "title": "Zebra", "url": "http://x/z", "cls": "c", "evidence": "E1"},
        {"severity": "low", "title": "Alpha", "url": "http://x/a", "cls": "c", "evidence": "E2"},
    ])
    asc = client.get(f"/scans/{sid}/findings?sort=title&dir=asc", headers=h).json()["items"]
    assert [x["title"] for x in asc] == ["Alpha", "Zebra"]
    desc = client.get(f"/scans/{sid}/findings?sort=title&dir=desc", headers=h).json()["items"]
    assert [x["title"] for x in desc] == ["Zebra", "Alpha"]
    alpha = next(x for x in asc if x["title"] == "Alpha")
    assert alpha["raw"].get("evidence") == "E2" and alpha["cls"] == "c"    # full boxcutter item preserved


def test_findings_export_csv_json(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="exp-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="exp-t")
    sid = client.post("/scans", json={"name": "exp", "template_id": tid, "targets": ["example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    runner.run_one([{"severity": "high", "title": "XSS", "url": "http://x", "cls": "xss", "evidence": "E"}])
    r = client.get(f"/scans/{sid}/findings/export?format=csv", headers=h)
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "") and "severity" in r.text and "XSS" in r.text
    rj = client.get(f"/scans/{sid}/findings/export?format=json", headers=h)
    assert "application/json" in rj.headers["content-type"] and any(x["title"] == "XSS" for x in rj.json())
    assert client.get(f"/scans/{sid}/findings/export?format=json&severity=Critical", headers=h).json() == []


def test_jobs_counts_and_status_filter(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="jc-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="jc-t")
    sid = client.post("/scans", json={"name": "jc", "template_id": tid, "targets": ["t1", "t2"],
                                      "authorized": True}, headers=h).json()["id"]
    r = client.get(f"/scans/{sid}/jobs", headers=h).json()
    assert r["total"] == 2 and r["counts"].get("pending") == 2
    runner.run_one([])                                    # complete one of this scan's jobs
    done = client.get(f"/scans/{sid}/jobs?status=done", headers=h).json()
    assert done["total"] == 1 and all(j["status"] == "done" for j in done["items"])


def test_stats_overview(client):
    h = auth(login(client))
    r = client.get("/stats", headers=h).json()
    for k in ("scans_total", "findings_by_severity", "scanners_total", "recent_criticals",
              "active_scans", "trend", "recent_activity", "findings_open"):
        assert k in r


def test_global_findings_search(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="gf-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="gf-t")
    sid = client.post("/scans", json={"name": "gf", "template_id": tid, "targets": ["example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    runner.run_one([{"severity": "critical", "title": "UNIQUEXYZ", "url": "http://x", "cls": "c"}])
    r = client.get("/findings?q=UNIQUEXYZ", headers=h).json()
    assert any(f["title"] == "UNIQUEXYZ" and f["scan_id"] == sid for f in r["items"])
    assert "scan" in r["items"][0] and "next" in r        # cross-scan feed: scan name + keyset cursor


def test_activity_feed(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="act-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="act-t")
    sid = client.post("/scans", json={"name": "act", "template_id": tid, "targets": ["a.example.com"],
                                      "authorized": True}, headers=h).json()["id"]
    runner.run_one([])                                    # -> job_claimed + scan_done activity
    feed = client.get("/activity", headers=h).json()
    kinds = {a["kind"] for a in feed["items"]}
    assert {"scan_created", "job_claimed", "scan_done"} <= kinds and feed["total"] >= 3
    scoped = client.get(f"/activity?scan_id={sid}", headers=h).json()
    assert scoped["total"] >= 3 and all(a["scan_id"] == sid for a in scoped["items"])


def test_runner_concurrency_control(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="conc-runner")
    # admin asks the agent to run 6 boxcutters
    r = client.patch(f"/runners/{runner.id}", json={"concurrency": 6}, headers=h)
    assert r.status_code == 200 and r.json()["desired_slots"] == 6
    # heartbeat still reporting the old slots -> the command is delivered but not yet applied
    hb = client.post("/runner/heartbeat", json={"status": "idle", "slots": 1, "busy_slots": 0,
                                                "current_jobs": [], "version": "t"}, headers=runner.h).json()
    assert hb["desired_slots"] == 6
    # heartbeat reporting the adopted slots -> the one-shot command is cleared
    hb2 = client.post("/runner/heartbeat", json={"status": "idle", "slots": 6, "busy_slots": 0,
                                                 "current_jobs": [], "version": "t"}, headers=runner.h).json()
    assert hb2["desired_slots"] is None
    detail = client.get(f"/runners/{runner.id}", headers=h).json()
    assert detail["slots"] == 6 and detail["desired_slots"] is None
    # a non-admin can't command runners
    client.post("/users", json={"username": "bob", "password": "pw", "role": "user"}, headers=h)
    bh = auth(login(client, "bob", "pw"))
    assert client.patch(f"/runners/{runner.id}", json={"concurrency": 2}, headers=bh).status_code in (401, 403)


def test_import_dedupes_targets(client):
    h = auth(login(client))
    tid = _tool_template(client, h, name="dedup-t")
    sid = client.post("/scans", json={"name": "dedup", "template_id": tid, "targets": [
        "Example.com", "example.com", "example.com/", "example.com.", "  b.example.com  ", "b.example.com"]},
        headers=h).json()["id"]
    client.post(f"/scans/{sid}/stop", headers=h)          # don't leave pending jobs in the shared queue
    det = client.get(f"/scans/{sid}", headers=h).json()
    assert det["assets"] == 2                              # all example.com variants collapse; + b.example.com


def test_global_findings_keyset(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="keyset-runner")
    runner.drain(lambda t: [])                             # clear any pending jobs from earlier tests
    tid = _tool_template(client, h, name="keyset-t")
    client.post("/scans", json={"name": "keyset", "template_id": tid,
                                "targets": [f"n{i}.example.com" for i in range(6)]}, headers=h)
    runner.drain(lambda t: [{"severity": "low", "title": f"F-{t}", "url": f"http://{t}", "cls": "c"}])
    seen, cur, pages = [], None, 0
    while True:
        u = "/findings?limit=2" + (f"&before={cur}" if cur is not None else "")
        r = client.get(u, headers=h).json()
        ids = [f["id"] for f in r["items"]]
        assert ids == sorted(ids, reverse=True)            # most-recent (highest id) first within a page
        if cur is not None:
            assert all(i < cur for i in ids)               # keyset boundary: strictly older than the cursor
        seen += ids
        cur, pages = r["next"], pages + 1
        if cur is None or pages > 60:
            break
    assert len(seen) == len(set(seen))                     # no duplicates across pages
    assert len(seen) >= 6                                  # collected at least our 6 findings


def test_prune_logs_by_age(client):
    from datetime import datetime, timezone, timedelta
    from sqlmodel import Session, select
    from app.db import engine
    from app.activity import prune_logs
    from app.models import Activity
    with Session(engine) as s:
        s.add(Activity(kind="prune_old", message="old", at=datetime.now(timezone.utc) - timedelta(days=60)))
        s.add(Activity(kind="prune_new", message="new"))
        s.commit()
        assert prune_logs(s, 30) >= 1
        kinds = {a.kind for a in s.exec(select(Activity)).all()}
        assert "prune_new" in kinds and "prune_old" not in kinds
        assert prune_logs(s, 0) == 0                        # retention disabled -> no-op


def test_login_rate_limited(client):
    import app.routers.auth as auth_mod
    auth_mod._login_fails.clear()
    try:
        for _ in range(auth_mod._LOGIN_MAX):               # burn the allowed failures
            assert client.post("/auth/login", json={"username": "root", "password": "nope"}).status_code == 401
        r = client.post("/auth/login", json={"username": "root", "password": "nope"})
        assert r.status_code == 429 and "Retry-After" in r.headers      # now throttled
        # even a correct password is blocked during the cooldown for this source
        assert client.post("/auth/login", json={"username": "root", "password": "root"}).status_code == 429
    finally:
        auth_mod._login_fails.clear()                       # don't leak the block into other tests


def test_telegram_notify_config(client):
    h = auth(login(client))
    r = client.get("/notify/telegram", headers=h).json()
    assert r["enabled"] is False and r["has_token"] is False and "Critical" in r["severities"]
    r = client.post("/notify/telegram", json={"enabled": True, "chat_id": "123", "token": "SECRET",
                                              "severities": ["Critical", "High", "Medium", "bogus"]}, headers=h).json()
    assert r["enabled"] and r["chat_id"] == "123" and r["has_token"] is True
    assert set(r["severities"]) == {"Critical", "High", "Medium"}      # invalid severity dropped
    assert "token" not in r and "telegram_token" not in r             # the secret is never returned
    r = client.post("/notify/telegram", json={"chat_id": "456"}, headers=h).json()
    assert r["chat_id"] == "456" and r["has_token"] is True            # token kept when omitted
    client.post("/users", json={"username": "u2", "password": "pw", "role": "user"}, headers=h)
    uh = auth(login(client, "u2", "pw"))
    assert client.get("/notify/telegram", headers=uh).status_code in (401, 403)   # admin-only


def test_notify_findings_filters_by_severity(monkeypatch):
    import time as _t
    import app.notify as nmod
    sent = []
    monkeypatch.setattr(nmod, "send_telegram", lambda token, chat, text: sent.append(text))
    findings = [{"severity": "Critical", "title": "A", "url": "http://a"},
                {"severity": "Low", "title": "B", "url": "http://b"},
                {"severity": "High", "title": "C", "url": "http://c"}]
    nmod.notify_findings({"token": "t", "chat_id": "c", "severities": {"Critical", "High"}}, findings)
    _t.sleep(0.5)                                                      # the send runs in a daemon thread
    blob = " ".join(sent)
    assert "A" in blob and "C" in blob and "B" not in blob            # Low filtered out
    assert "Critical" in blob and "http://a" in blob                  # severity + url in the message


def test_delete_scan(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="del-runner")
    runner.drain(lambda t: [])
    tid = _tool_template(client, h, name="del-t")
    sid = client.post("/scans", json={"name": "to-delete", "template_id": tid,
                                      "targets": ["a.example.com"]}, headers=h).json()["id"]
    runner.run_one([{"severity": "high", "title": "F", "url": "http://a", "cls": "c"}])
    assert client.get(f"/scans/{sid}", headers=h).status_code == 200
    assert client.get(f"/scans/{sid}/findings", headers=h).json()["total"] >= 1
    assert client.delete(f"/scans/{sid}", headers=h).json()["ok"] is True
    assert client.get(f"/scans/{sid}", headers=h).status_code == 404          # scan gone
    assert client.get(f"/scans/{sid}/findings", headers=h).status_code == 404  # and its findings


def test_delete_scan_batches_drain_fully(client):
    """The batched delete must remove EVERY row even when there is more than one batch's worth (the loop must
    not stop after the first batch) — this is what keeps a 100k-row delete from wedging the write lock."""
    from sqlmodel import Session, select
    from app.db import engine
    from app.models import Target
    from app.routers.scans import _delete_scan_rows
    h = auth(login(client))
    tid = _tool_template(client, h, name="batch-del")
    sid = client.post("/scans", json={"name": "batchy", "template_id": tid,
                                      "targets": [f"h{i}.example.com" for i in range(5)],
                                      "authorized": True}, headers=h).json()["id"]
    with Session(engine) as s:
        assert len(s.exec(select(Target.id).where(Target.scan_id == sid)).all()) == 5
        _delete_scan_rows(s, Target, sid, batch=2)              # 5 rows, batch of 2 -> must loop 3x, not stop at 2
        assert s.exec(select(Target.id).where(Target.scan_id == sid)).first() is None
    client.delete(f"/scans/{sid}", headers=h)                  # clean up the (now child-less) scan row


def test_2fa_totp_flow(client):
    import time
    from sqlmodel import Session, select
    from app.db import engine
    from app.models import User
    from app.security import _totp_code
    h = auth(login(client))
    try:
        assert client.get("/auth/2fa", headers=h).json()["enabled"] is False
        r = client.post("/auth/2fa/setup", headers=h).json()
        secret = r["secret"]
        assert secret and r["otpauth_uri"].startswith("otpauth://totp/")
        assert client.post("/auth/2fa/enable", json={"code": "000000"}, headers=h).status_code == 400   # wrong
        assert client.post("/auth/2fa/enable", json={"code": _totp_code(secret, time.time())},
                           headers=h).json()["enabled"] is True
        # login now needs a code
        r = client.post("/auth/login", json={"username": "root", "password": "root"})
        assert r.status_code == 401 and "2fa" in r.json()["detail"].lower()
        r = client.post("/auth/login", json={"username": "root", "password": "root",
                                             "code": _totp_code(secret, time.time())})
        assert r.status_code == 200 and "token" in r.json()
        # disable -> no code needed again
        assert client.post("/auth/2fa/disable", json={"code": _totp_code(secret, time.time())},
                           headers=h).json()["enabled"] is False
        assert client.post("/auth/login", json={"username": "root", "password": "root"}).status_code == 200
    finally:
        with Session(engine) as s:                      # bulletproof cleanup so 2FA never leaks to other tests
            u = s.exec(select(User).where(User.username == "root")).first()
            if u:
                u.totp_enabled = False
                u.totp_secret = None
                s.add(u)
                s.commit()


def test_delete_runner(client):
    h = auth(login(client))
    runner = FakeRunner(client, name="del-runner-r")
    runner.heartbeat()
    assert any(r["id"] == runner.id for r in client.get("/runners", headers=h).json())
    assert client.delete(f"/runners/{runner.id}", headers=h).json()["ok"] is True
    assert not any(r["id"] == runner.id for r in client.get("/runners", headers=h).json())
    # non-admin can't remove scanners
    client.post("/users", json={"username": "u3", "password": "pw", "role": "user"}, headers=h)
    uh = auth(login(client, "u3", "pw"))
    r2 = FakeRunner(client, name="del-runner-r2")
    assert client.delete(f"/runners/{r2.id}", headers=uh).status_code in (401, 403)


def test_build_argv_subcommand_by_kind():
    import json as _json
    from app.routers.runners import build_argv

    class _T:
        def __init__(self, kind, name):
            self.kind, self.context, self.llm_profile_id = kind, None, None
            self.spec_json = _json.dumps({"name": name, "params": []})

    assert build_argv(None, _T("tool", "httpx"), "example.com")[0] == ["httpx", "example.com"]
    assert build_argv(None, _T("workflow", "web-full"), "example.com")[0] == ["workflow", "web-full", "example.com"]
    assert build_argv(None, _T("ai_agent", "irvin"), "example.com")[0] == ["ai", "irvin", "example.com"]


def test_llm_profile_patch_sets_key(client):
    h = auth(login(client))
    pid = client.post("/llm-profiles", json={"name": "patch-me", "provider": "anthropic"}, headers=h).json()["id"]
    assert next(p for p in client.get("/llm-profiles", headers=h).json() if p["id"] == pid)["has_key"] is False
    r = client.patch(f"/llm-profiles/{pid}", json={"api_key": "sk-new", "model": "claude-x"}, headers=h)
    assert r.status_code == 200 and r.json()["has_key"] is True
    after = next(p for p in client.get("/llm-profiles", headers=h).json() if p["id"] == pid)
    assert after["has_key"] is True and after["model"] == "claude-x"
