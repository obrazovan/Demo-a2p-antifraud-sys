"""
FastAPI application entrypoint for the Analytics Ingestion & Reporting Service.
Consumes 'inspection.completed' events from RabbitMQ queue 'analytics.raw_events',
batches inserts into ClickHouse `sms_inspections`, and exposes last-hour summary stats.
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

# Ensure repository root is available for shared package imports
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

try:
    from shared.logger import get_logger, request_context, set_request_id
except ImportError:
    _fallback_req_id: ContextVar[Optional[str]] = ContextVar("analytics_req_id", default=None)

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
from .consumer import AnalyticsConsumer
from .schemas import AnalyticsSummaryResponse, HealthResponse, ReadyResponse
from .storage import ClickHouseStorage

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

_storage = ClickHouseStorage()
_consumer = AnalyticsConsumer(storage=_storage)


def get_storage() -> ClickHouseStorage:
    """FastAPI dependency returning the ClickHouse storage adapter."""
    return _storage


def get_consumer() -> AnalyticsConsumer:
    """FastAPI dependency returning the RabbitMQ analytics consumer."""
    return _consumer


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initializes ClickHouse schema and starts RabbitMQ batch consumer."""
    logger.info("Analytics Service starting up...")
    try:
        await _storage.connect_and_init()
    except Exception as exc:
        logger.warning(
            "ClickHouse initial connection failed (%s: %s); /ready will report 503 until available",
            type(exc).__name__,
            exc,
        )

    try:
        await _consumer.start()
    except Exception as exc:
        logger.warning(
            "RabbitMQ consumer startup warning (%s: %s); HTTP API remains available",
            type(exc).__name__,
            exc,
        )

    yield

    logger.info("Analytics Service shutting down...")
    await _consumer.stop()
    await _storage.close()


app = FastAPI(
    title="Analytics Ingestion & Reporting Service",
    description=(
        "Consumes inspection.completed events from RabbitMQ in batches, writes to "
        "ClickHouse MergeTree storage, and serves aggregated anti-fraud statistics."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Middlewares
# ============================================================================

@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    """Extracts X-Request-ID header (or generates UUID4) and logs structured JSON."""
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
    logger.error("Unhandled exception in Analytics Service: %s", exc, exc_info=True)
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
    """Immediate liveness probe returning HTTP 200 if service process is alive."""
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
    storage: ClickHouseStorage = Depends(get_storage),
    consumer: AnalyticsConsumer = Depends(get_consumer),
) -> ReadyResponse | JSONResponse:
    """Verifies active ClickHouse database connectivity."""
    is_ready, error_detail = await storage.check_ready()
    if not is_ready:
        logger.warning("Readiness probe failed: %s", error_detail)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "error",
                "clickhouse": "disconnected",
                "database": storage.database,
                "service": settings.SERVICE_NAME,
                "detail": error_detail,
            },
        )
    return ReadyResponse(
        status="ready",
        clickhouse="connected",
        database=storage.database,
        service=settings.SERVICE_NAME,
        consumer_connected=consumer.is_connected,
        buffered_events=consumer.buffered_count,
    )


# ============================================================================
# Business Endpoints
# ============================================================================

@app.get(
    "/api/v1/stats/summary",
    response_model=AnalyticsSummaryResponse,
    tags=["Analytics"],
    summary="Last-Hour Traffic Summary Statistics",
)
async def get_stats_summary(
    storage: ClickHouseStorage = Depends(get_storage),
) -> AnalyticsSummaryResponse:
    """
    Returns aggregated anti-fraud statistics over the last 1 hour:
    total inspections, blocked (DENY) count, allowed (ALLOW) count,
    block rate percentage, average latency (ms), and average risk score.
    """
    try:
        return await storage.get_last_hour_summary()
    except Exception as exc:
        logger.error("Failed to query ClickHouse stats summary: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analytics storage is temporarily unavailable",
        )
