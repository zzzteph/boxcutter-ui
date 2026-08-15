# boxcutter-ui

A small self-hosted web UI for the [boxcutter](https://github.com/zzzteph/boxcutter) scanner. Log in, create a
scan, paste some targets, pick a workflow / tool / AI agent, and watch the findings come in. Scans run on
separate agent machines that pull jobs from the server over HTTP.

> Only scan systems you're allowed to test.

## All-in-one (quickest)

One container = the server **and** one built-in agent (runs 4 scans at once):

```bash
docker run -d --restart unless-stopped -p 8000:8000 \
  -v boxcutter-data:/app/data ghcr.io/zzzteph/boxcutter-standalone
```

Open <http://localhost:8000>, log in **root / root**, and start scanning. To scale out later, run the split
server + separate agents below (they can point at this same server too).

## Run the server

```bash
docker run -d --name boxcutter-server --restart unless-stopped -p 8000:8000 \
  -v boxcutter-data:/app/data ghcr.io/zzzteph/boxcutter-server
```

Open <http://localhost:8000> and log in with **root / root** (it'll ask you to change the password). Nothing
else to set up — the database and signing key are created on first run and kept in the `boxcutter-data` volume.

Behind nginx or Cloudflare, just proxy port 8000 — it's a single origin. One caveat: don't buffer the live-log
stream, e.g. `location ~ /scans/.*/stream$ { proxy_pass http://127.0.0.1:8000; proxy_buffering off; }`.

## Add an agent

In the UI go to **Scanners** and create an enroll token. Then, on any machine that can reach the server:

```bash
docker run -d --name boxcutter-agent --restart unless-stopped -p 127.0.0.1:7070:7070 \
  -e SERVER_URL=https://your-server -e ENROLL_TOKEN=<token> -e CONCURRENCY=5 \
  ghcr.io/zzzteph/boxcutter-agent
```

`CONCURRENCY` is how many scans it runs at once — change it any time from the server's **Scanners** page, or
from the agent's own page at <http://127.0.0.1:7070> (login `root / root`, where you can also set the server URL
and token instead of the env vars). Run it on as many machines as you like; if an agent or a job crashes it
recovers on its own.

## Notes

- Images are prebuilt and published to GHCR — just `docker pull`/`run`, no local build. The server is
  multi-arch (amd64 + arm64); the agent and standalone are amd64.
- **Telegram alerts:** in **Settings → Telegram notifications** (admin), set a bot token + chat id and tick
  which severities to be pinged on — you get one message (severity + info + URL) per new finding.
- **Big imports are fine:** paste tens of thousands of targets into one scan — they're de-duplicated, and the
  lists/findings stay paginated and fast.
- Want MariaDB or Postgres instead of SQLite? Add `-e DATABASE_URL=…` to the server.
- Optional env: `ACTIVITY_RETENTION_DAYS` (default 30) trims old log rows; set `SECRET_KEY` only if you run
  multiple server replicas. REST API docs (Swagger) live at `/docs`.
