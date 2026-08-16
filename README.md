# boxcutter-ui

A small self-hosted web UI for the [boxcutter](https://github.com/zzzteph/boxcutter) scanner. Log in, create a
scan, paste some targets, pick a workflow / tool / AI agent, and watch the findings come in. Scanning runs on
the server's built-in agent and/or on separate agent machines that pull jobs over HTTP.

> Only scan systems you're allowed to test.

## Run the server

One container is the whole thing — the API, the web UI, and a built-in agent:

```bash
docker run -d --name boxcutter-server --restart unless-stopped -p 8000:8000 \
  -v boxcutter-data:/app/data ghcr.io/zzzteph/boxcutter-server
```

Open <http://localhost:8000> and log in with **root / root** (it'll ask you to change the password). Nothing
else to set up — the database and signing key are created on first run and kept in the `boxcutter-data` volume.

The built-in agent starts **idle** (0 boxcutters). Open **Scanners** and give it a concurrency to scan from the
server host itself — or leave it at 0 and add separate agents below. (It's a permanent fixture: adjust it to 0
or more, but it can't be removed.)

Behind nginx or Cloudflare, just proxy port 8000 — it's a single origin. One caveat: don't buffer the live-log
stream, e.g. `location ~ /scans/.*/stream$ { proxy_pass http://127.0.0.1:8000; proxy_buffering off; }`.

## Add an agent (scale out)

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

- Images are prebuilt and published to GHCR — just `docker pull`/`run`, no local build. Both images (server +
  agent) are multi-arch: amd64 + arm64.
- **Telegram alerts:** in **Settings → Telegram notifications** (admin), set a bot token + chat id and tick
  which severities to be pinged on — you get one message (severity + info + URL) per new finding.
- **Big imports are fine:** paste tens of thousands of targets into one scan — they're de-duplicated, and the
  lists/findings stay paginated and fast.
- Want MariaDB or Postgres instead of SQLite? Add `-e DATABASE_URL=…` to the server.
- Optional env: `ACTIVITY_RETENTION_DAYS` (default 30) trims old log rows; set `SECRET_KEY` only if you run
  multiple server replicas. REST API docs (Swagger) live at `/docs`.
