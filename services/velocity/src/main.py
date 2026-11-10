"""
FastAPI application entrypoint for the Velocity Service.
Provides high-speed Redis sliding-window frequency tracking,
structured JSON logging with X-Request-ID correlation, and health/readiness probes.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Optional
from uuid import uuid4

# Ensure project root is available for shared package imports
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

try:
    from shared.logger import get_logger, request_context, set_request_id
except ImportError:
    _fallback_req_id: ContextVar[Optional[str]] = ContextVar("velocity_req_id", default=None)

    class _FallbackJSONFormatter(logging.Formatter):
        def __init__(self, service_name: str) -> None:
            super().__init__()
            self.service_name = service_name

        def format(self, record: logging.LogRecord) -> str:
            req_id = getattr(record, "request_id", None) or _fallback_req_id.get()
            dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
            payload: dict[str, Any] = {
                "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "service": self.service_name,
                "level": record.levelname,
                "request_id": str(req_id) if req_id is not None else None,
                "message": record.getMessage(),
            }
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False)

    def get_logger(service_name: str, level: str = "INFO") -> logging.Logger:
        log = logging.getLogger(service_name)
        log.setLevel(getattr(logging, level.upper(), logging.INFO))
        log.propagate = False
        if log.hasHandlers():
            log.handlers.clear()
        handler = logging.StreamHandler()
        handler.setFormatter(_FallbackJSONFormatter(service_name))
        log.addHandler(handler)
        return log

    def set_request_id(request_id: Optional[str]) -> None:
        _fallback_req_id.set(request_id)

    @contextmanager
    def request_context(request_id: str):
        token = _fallback_req_id.set(request_id)
        try:
            yield
        finally:
            _fallback_req_id.reset(token)

from .config import settings
from .redis_client import (
    check_redis_ready,
    close_redis,
    get_redis_client,
    init_redis,
    record_velocity_hit,
)
from .schemas import (
    HealthResponse,
    ReadyResponse,
    VelocityHitRequest,
    VelocityHitResponse,
)

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initializes and cleanly shuts down the Redis async connection pool."""
    logger.info("Velocity Service starting up...")
    await init_redis()
    logger.info("Redis client pool initialized for %s", settings.REDIS_URL)

    yield

    logger.info("Velocity Service shutting down...")
    await close_redis()


app = FastAPI(
    title="Velocity Service",
    description="High-speed sliding-window frequency tracking backed by Redis Sorted Sets.",
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Middlewares
# ============================================================================

@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    """Extracts X-Request-ID header, binds logging context, and logs request latency."""
    raw_header = request.headers.get("X-Request-ID")
    request_id = raw_header.strip() if raw_header and raw_header.strip() else str(uuid4())
    request.state.request_id = request_id
    set_request_id(request_id)

    start_time = time.perf_counter()
    with request_context(request_id):
        logger.info("Incoming %s %s", request.method, request.url.path)
        response: Response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "Completed %s %s status=%d latency_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response


# ============================================================================
# Exception Handlers (Standardized Error Envelopes - No stack leaks)
# ============================================================================

def _extract_request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = _extract_request_id(request)
    return JSONResponse(
        status_code=exc.status_code,
        headers={"X-Request-ID": request_id} if request_id else None,
        content={
            "error_code": "HTTP_ERROR",
            "message": exc.detail,
            "request_id": request_id,
            "details": None,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = _extract_request_id(request)
    return JSONResponse(
        status_code=HTTP_422_STATUS,
        headers={"X-Request-ID": request_id} if request_id else None,
        content={
            "error_code": "VALIDATION_ERROR",
            "message": "Input validation error",
            "request_id": request_id,
            "details": jsonable_encoder(exc.errors()),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = _extract_request_id(request)
    logger.error("Unhandled exception during velocity request: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        headers={"X-Request-ID": request_id} if request_id else None,
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected internal server error occurred",
            "request_id": request_id,
            "details": None,
        },
    )


# ============================================================================
# Health & Readiness Endpoints
# ============================================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Liveness Probe",
)
async def health_check() -> HealthResponse:
    """Immediate liveness probe returning HTTP 200 if service is responsive."""
    return HealthResponse(
        status="ok",
        service=settings.SERVICE_NAME,
    )


@app.get(
    "/ready",
    response_model=ReadyResponse,
    tags=["System"],
    summary="Readiness Probe",
)
async def readiness_check(
    redis_client: Optional[aioredis.Redis] = Depends(get_redis_client),
) -> ReadyResponse | JSONResponse:
    """Pings Redis to confirm cache connectivity within strict timeout."""
    is_ready, error_detail = await check_redis_ready(redis_client)
    if not is_ready:
        logger.warning("Readiness probe failed: %s", error_detail)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "error",
                "redis": "disconnected",
                "service": settings.SERVICE_NAME,
                "detail": error_detail,
            },
        )
    return ReadyResponse(
        status="ready",
        redis="connected",
        service=settings.SERVICE_NAME,
    )


# ============================================================================
# Business Endpoints
# ============================================================================

@app.post(
    "/api/v1/velocity/hit",
    response_model=VelocityHitResponse,
    tags=["Velocity"],
    summary="Record Hit and Return Sliding-Window Frequencies",
)
async def register_velocity_hit(
    payload: VelocityHitRequest,
    redis_client: Optional[aioredis.Redis] = Depends(get_redis_client),
) -> VelocityHitResponse:
    """
    Atomically increments sliding-window counters for client_ip (60s)
    and phone_number (300s) and returns current frequencies.
    Falls back safely to (0, 0) on Redis timeouts or connection failures.
    """
    ip_count_1m, phone_count_5m = await record_velocity_hit(
        redis_client,
        ip=payload.ip,
        phone=payload.phone,
    )
    logger.info(
        "Velocity hit processed: ip=%s ip_count_1m=%d phone=%s phone_count_5m=%d",
        payload.ip,
        ip_count_1m,
        payload.phone,
        phone_count_5m,
    )
    return VelocityHitResponse(
        ip_count_1m=ip_count_1m,
        phone_count_5m=phone_count_5m,
    )
