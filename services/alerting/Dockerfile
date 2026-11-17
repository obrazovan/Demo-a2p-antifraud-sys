# ============================================================================
# Multi-stage Dockerfile for Alerting & Security Audit Microservice
# ============================================================================

# Stage 1: Build virtual environment
FROM python:3.11-slim AS builder

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY services/alerting/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# Stage 2: Minimal runtime image with unprivileged user
FROM python:3.11-slim AS runner

RUN groupadd -r appgroup && useradd -r -g appgroup -u 1001 -m appuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app" \
    SQLITE_DB_PATH="/data/alerts_audit.db"

COPY shared/ /app/shared/
COPY services/alerting/src/ /app/src/

RUN mkdir -p /data && chown -R appuser:appgroup /app /data

USER appuser

EXPOSE 8006

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8006/health')" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8006"]
