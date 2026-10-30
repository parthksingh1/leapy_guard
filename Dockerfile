# Leaply Guard web demo. Works on Render (uses $PORT) and Hugging Face Spaces (port 7860).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    UV_CACHE_DIR=/app/.uv-cache UV_LINK_MODE=copy \
    LEAPLY_HOSTED=1 PORT=7860 HOME=/app

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv==0.5.11

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY leaply_guard ./leaply_guard
RUN pip install --no-cache-dir .

COPY demo ./demo
COPY replays ./replays

# Warm the package cache so live demo runs create their sandboxes in seconds
RUN uv venv -q /tmp/warm && uv pip install -q -p /tmp/warm -r demo/vulnerable-app/requirements.txt \
 && uv pip install -q -p /tmp/warm "PyJWT==2.15.1" && rm -rf /tmp/warm \
 && mkdir -p runs && chmod -R a+rwX /app

EXPOSE 7860
CMD ["sh", "-c", "uvicorn leaply_guard.server:app --host 0.0.0.0 --port ${PORT:-7860} --proxy-headers --forwarded-allow-ips='*'"]
