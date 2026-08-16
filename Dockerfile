# Single Dockerfile for the whole project. Two images come out of it via build targets (same context "."):
#
#   docker build --target server -t boxcutter-server .   # all-in-one: API + built SPA + one built-in agent
#   docker build --target agent  -t boxcutter-agent  .   # scanner = boxcutter image + supervisor (scale out)
#
# `docker build .` with no target builds the server (the last stage). GitHub Actions builds both targets, each
# multi-arch (amd64 + arm64). Put TLS (a reverse proxy) in front of the server for remote agents/browsers.

# ---- stage: build the Vue SPA (VITE_API_BASE unset -> same-origin/relative API calls) ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- target: boxcutter-agent (the scale-out scanner) ----
FROM ghcr.io/zzzteph/boxcutter:latest AS agent
COPY runner/supervisor.py /supervisor.py
# The engine is not a bare `boxcutter` command — the base image runs it via python (its ENTRYPOINT is
# `python3 /opt/boxcutter/boxcutter.py`). Point the supervisor at that. Override BOXCUTTER_CMD if a future base
# image moves it.
ENV BOXCUTTER_CMD="python3 /opt/boxcutter/boxcutter.py" \
    RUNNER_UI_PORT=7070 \
    RUNNER_CONFIG=/data/runner-config.json
VOLUME ["/data"]
EXPOSE 7070
ENTRYPOINT ["python3", "/supervisor.py"]

# ---- target: boxcutter-server (all-in-one: API + built SPA + ONE built-in agent) — default target ----
# FROM the engine image so the built-in agent can run boxcutter. The engine's base marks the system python
# "externally managed" (PEP 668), so the server's own deps go into a dedicated venv; the launcher runs uvicorn +
# one auto-enrolled agent that starts IDLE (0 boxcutters) — raise it from the Scanners page, or add separate
# boxcutter-agent containers to scale out. The `boxcutter` engine keeps using its own on-PATH python install.
#   docker run -d -p 8000:8000 -v boxcutter-data:/app/data boxcutter-server
FROM ghcr.io/zzzteph/boxcutter:latest AS server
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app BOXCUTTER_CMD="python3 /opt/boxcutter/boxcutter.py" RUNNER_UI_PORT=7070
RUN python3 -m venv /opt/srv \
 && /opt/srv/bin/pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" "sqlmodel>=0.0.16" \
    "pydantic-settings>=2.2" "passlib[bcrypt]>=1.7" "bcrypt>=4.0.1,<4.1" "pyjwt>=2.8" \
    "python-multipart>=0.0.9" "pymysql>=1.1" "requests>=2.31"
COPY api/app ./app
COPY runner/supervisor.py /supervisor.py
COPY deploy/launch.py /launch.py
COPY --from=web /web/dist ./web_dist
# holds the SQLite DB + the auto-generated JWT secret; mount a named volume to persist across restarts
VOLUME ["/app/data"]
EXPOSE 8000 7070
ENTRYPOINT ["/opt/srv/bin/python", "/launch.py"]
