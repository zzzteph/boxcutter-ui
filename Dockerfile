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
# How the supervisor invokes the engine. If `boxcutter` is not a bare command on PATH in the image, set this to
# the real invocation (e.g. "python3 /app/boxcutter.py") — verify against the image and adjust.
ENV BOXCUTTER_CMD=boxcutter \
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
