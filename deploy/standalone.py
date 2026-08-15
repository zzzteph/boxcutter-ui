#!/usr/bin/env python3
"""boxcutter-standalone launcher.

Runs the whole product in ONE container: the server (API + SPA on :8000) plus one built-in agent that
auto-enrolls to the local server. For a quick single-host deploy:

    docker run -d -p 8000:8000 -v boxcutter-data:/app/data ghcr.io/zzzteph/boxcutter-standalone

The built-in agent runs CONCURRENCY scans in parallel (default 4). To scale out, add more separate
boxcutter-agent containers pointed at this server's URL — this one keeps working alongside them.
"""
from __future__ import annotations

import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request


def log(msg: str) -> None:
    print(f"[standalone] {msg}", flush=True)


def wait_healthy(proc: subprocess.Popen, url: str, tries: int = 90) -> bool:
    for _ in range(tries):
        if proc.poll() is not None:
            return False
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return True
        except Exception:
            time.sleep(1)
    return False


def main() -> int:
    # A shared enroll token: the server seeds it (via ENROLL_TOKEN), the built-in agent enrolls with it.
    token = os.environ.get("ENROLL_TOKEN") or secrets.token_urlsafe(24)
    os.environ["ENROLL_TOKEN"] = token

    log("starting server on :8000")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000",
         "--proxy-headers", "--forwarded-allow-ips", "*"],
        cwd="/app", env=dict(os.environ))

    if not wait_healthy(server, "http://127.0.0.1:8000/health"):
        log("server did not become healthy — aborting")
        try:
            server.terminate()
        except Exception:
            pass
        return 1
    log("server healthy")

    agent_env = dict(os.environ)
    agent_env["SERVER_URL"] = "http://127.0.0.1:8000"
    agent_env["ENROLL_TOKEN"] = token
    agent_env.setdefault("CONCURRENCY", "4")
    agent_env.setdefault("RUNNER_UI_PORT", "7070")
    agent_env.setdefault("RUNNER_NAME", "standalone")
    log(f"starting built-in agent (concurrency={agent_env['CONCURRENCY']})")
    agent = subprocess.Popen([sys.executable, "/supervisor.py"], env=agent_env)

    procs = {"server": server, "agent": agent}

    def shutdown(*_):
        for p in procs.values():
            try:
                p.terminate()
            except Exception:
                pass

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Self-heal: if the agent dies (e.g. OOM-killed while scanning) restart just it and keep the server up.
    # If the SERVER dies, stop the container so Docker restarts it clean. A fast agent crash-loop also bails
    # out to a clean container restart rather than spinning.
    restarts, last_start = 0, time.time()
    while True:
        if server.poll() is not None:
            log(f"server exited ({server.returncode}); stopping so Docker restarts the container")
            try:
                procs["agent"].terminate()
            except Exception:
                pass
            return server.returncode or 1
        if procs["agent"].poll() is not None:
            now = time.time()
            if now - last_start > 60:
                restarts = 0
            restarts += 1
            if restarts > 5:
                log("agent crash-looping; stopping so Docker restarts the container clean")
                return 1
            log(f"agent exited ({procs['agent'].returncode}); restarting it (attempt {restarts})")
            time.sleep(min(2 * restarts, 10))
            procs["agent"] = subprocess.Popen([sys.executable, "/supervisor.py"], env=agent_env)
            last_start = time.time()
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
