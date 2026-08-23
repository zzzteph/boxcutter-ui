# boxcutter agent (scanner)

The agent is the stock `ghcr.io/zzzteph/boxcutter` image plus `supervisor.py` (standard library only). It
enrolls with the boxcutter-server, runs N concurrent job slots, streams engine output back, and heartbeats. It
also serves a small local control UI (login) on `127.0.0.1:$RUNNER_UI_PORT`.

## Run it

The agent is the `agent` target of the repo's single `Dockerfile`. Build and run it with plain `docker`:

```bash
docker build --target agent -t boxcutter-agent ..
docker run -d --name boxcutter-agent \
  -e SERVER_URL=https://your-server -e ENROLL_TOKEN=<from the Scanners page> -e CONCURRENCY=3 \
  -p 127.0.0.1:7070:7070 boxcutter-agent
```

Or straight from the stock image, self-bootstrapping `supervisor.py` from the server (no build):

```bash
docker run -d --name boxcutter-agent \
  -e SERVER_URL=https://your-server -e ENROLL_TOKEN=<from the Scanners page> -e CONCURRENCY=3 \
  -p 127.0.0.1:7070:7070 \
  --entrypoint python3 ghcr.io/zzzteph/boxcutter \
  -c "import urllib.request; exec(urllib.request.urlopen('https://your-server/runner.py').read())"
```

Then open `http://127.0.0.1:7070` (login `root/root`) to set the server, paste an enroll token, and set the
number of boxcutters (instances).

## Config

Env (or the local UI, which persists to `$RUNNER_CONFIG`):

- `SERVER_URL` — the core server.
- `ENROLL_TOKEN` — an enroll token from the server Fleet page (or `RUNNER_USER`/`RUNNER_PASSWORD`).
- `CONCURRENCY` — number of parallel boxcutter jobs (changeable live from the UI).
- `BOXCUTTER_CMD` — how to invoke the engine (default `boxcutter`).
- `BOXCUTTER_VERSION` — pin the engine version shown on the Scanners page instead of probing for it.
- `JOB_IDLE_TIMEOUT` — kill a job after N seconds of silence. **0 (off)** by default; a deep scan is legitimately
  quiet for long stretches, so a silence clock kills real work.
- `JOB_MAX_RUNTIME` — absolute backstop, seconds. **21600 (6h)** by default, so a wedged engine can't hold a
  worker slot forever. Raise it if your scans legitimately run longer; `0` disables it entirely.
- `RUNNER_UI_PORT` — local control UI port (default 7070).

## Notes

- The agent reports **two** versions: the supervisor's own (`Agent`) and the boxcutter engine it actually runs
  (`Boxcutter`), which it gets by asking the engine once at startup (`--version`, falling back to the installed
  source). The engine is baked into the image, so that value only changes when the image is rebuilt — which is
  exactly how you confirm a rebuild picked up a newer boxcutter. The GHCR images are rebuilt daily by the
  `build-images` workflow (with `pull: true`, so the `ghcr.io/zzzteph/boxcutter:latest` base is re-resolved
  every run); pull a fresh agent image and restart to move a scanner onto the newer engine.
- The supervisor streams the engine's **stderr** as live events (that is where the live log and per-agent
  reasoning are) and parses **stdout** as the findings envelope. Agents that print a markdown report to stdout
  (e.g. `irvin`) are stored as a report; tools/workflows return a JSON envelope parsed into findings.
- LLM api keys arrive per job from the server and are set only in that subprocess's environment; they are
  never written to disk or logged.
