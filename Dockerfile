# Single Dockerfile for the whole project. Two images come out of it via build targets (same context "."):
#
#   docker build --target server -t boxcutter-server .   # API + built SPA (single origin)
#   docker build --target agent  -t boxcutter-agent  .   # scanner = boxcutter image + supervisor
#
# `docker build .` with no target builds the server (the last stage). GitHub Actions builds both targets.
# Put TLS (a reverse proxy) in front of the server for remote agents/browsers.

# ---- stage: build the Vue SPA (VITE_API_BASE unset -> same-origin/relative API calls) ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- stage: the API (no SPA) — used directly as the dev api, and as the base for `server` ----
FROM python:3.12-slim AS apibase
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app
COPY api/pyproject.toml ./
RUN pip install --no-cache-dir -e . || pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" "sqlmodel>=0.0.16" \
    "pydantic-settings>=2.2" "passlib[bcrypt]>=1.7" "bcrypt>=4.0.1,<4.1" "pyjwt>=2.8" \
    "python-multipart>=0.0.9" "pymysql>=1.1"
COPY api/app ./app
COPY runner ./runner
EXPOSE 8000
# --proxy-headers + trust all forwarders so it sits correctly behind nginx / Cloudflare (honours X-Forwarded-*).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]

# ---- target: boxcutter-agent (the scanner) ----
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

# ---- target: boxcutter-server (API + built SPA, single origin) — default target ----
FROM apibase AS server
COPY --from=web /web/dist ./web_dist
# SQLite DB + the auto-generated JWT secret live here; mount a named volume to persist across restarts.
VOLUME ["/app/data"]

# ---- target: boxcutter-standalone (server + ONE built-in agent, all in one container) ----
# FROM the engine image so `boxcutter` is on PATH; we add the server deps/code, the built SPA, the supervisor,
# and a launcher that runs uvicorn + one auto-enrolled agent together.
#   docker run -d -p 8000:8000 -v boxcutter-data:/app/data boxcutter-standalone
# NOTE: the server needs Python >= 3.10 (3.10+ typing). This assumes the boxcutter base ships a modern python;
# if it doesn't, use the two separate images instead. amd64 only (the engine base is amd64).
FROM ghcr.io/zzzteph/boxcutter:latest AS standalone
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app BOXCUTTER_CMD="python3 /opt/boxcutter/boxcutter.py" CONCURRENCY=4 RUNNER_UI_PORT=7070
# The engine's base marks the system python "externally managed" (PEP 668), so install the server deps into
# their own venv. The launcher runs uvicorn + the supervisor from this venv; the `boxcutter` engine keeps using
# its own on-PATH install.
RUN python3 -m venv /opt/srv \
 && /opt/srv/bin/pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.27" "sqlmodel>=0.0.16" \
    "pydantic-settings>=2.2" "passlib[bcrypt]>=1.7" "bcrypt>=4.0.1,<4.1" "pyjwt>=2.8" \
    "python-multipart>=0.0.9" "pymysql>=1.1" "requests>=2.31"
COPY api/app ./app
COPY runner/supervisor.py /supervisor.py
COPY deploy/standalone.py /standalone.py
COPY --from=web /web/dist ./web_dist
# holds the SQLite DB + the auto-generated JWT secret; mount a named volume to persist across restarts
VOLUME ["/app/data"]
EXPOSE 8000 7070
ENTRYPOINT ["/opt/srv/bin/python", "/standalone.py"]
