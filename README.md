# boxcutter-ui

A small self-hosted web UI for the [boxcutter](https://github.com/zzzteph/boxcutter) scanner. Log in, create a
scan, paste some targets, pick a workflow / tool / AI agent, and watch the findings come in. Scans run on
separate agent machines that pull jobs from the server over HTTP.

> Only scan systems you're allowed to test.

## Run the server

```bash
docker run -d --name boxcutter-server -p 8000:8000 \
  -v boxcutter-data:/app/data ghcr.io/zzzteph/boxcutter-server
```

Open <http://localhost:8000> and log in with **root / root** (it'll ask you to change the password). Nothing
else to set up — the database and signing key are created on first run and kept in the `boxcutter-data` volume.

Behind nginx or Cloudflare, just proxy port 8000 — it's a single origin. One caveat: don't buffer the live-log
stream, e.g. `location ~ /scans/.*/stream$ { proxy_pass http://127.0.0.1:8000; proxy_buffering off; }`.

## Add an agent

In the UI go to **Scanners** and create an enroll token. Then, on any machine that can reach the server:

```bash
docker run -d --name boxcutter-agent -p 127.0.0.1:7070:7070 \
  -e SERVER_URL=https://your-server -e ENROLL_TOKEN=<token> -e CONCURRENCY=5 \
  ghcr.io/zzzteph/boxcutter-agent
```

`CONCURRENCY` is how many scans it runs at once. You can also skip the env vars and set the server URL, token,
and scanner count from the agent's own page at <http://127.0.0.1:7070> (login `root / root`). Run it on as many
machines as you like.

## Notes

- Images are prebuilt and published to GHCR — just `docker pull`/`run`, no local build. The server is
  multi-arch (amd64 + arm64); the agent is amd64.
- Want MariaDB or Postgres instead of SQLite? Add `-e DATABASE_URL=…` to the server.
- REST API docs (Swagger) are at `/docs`.
