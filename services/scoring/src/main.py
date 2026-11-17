"""
FastAPI application entrypoint for the Scoring Service.
Orchestrates Rule Engine, Reputation, and Velocity microservices concurrently,
computes dynamic risk scores (ALLOW / DENY), publishes InspectionResult events
to RabbitMQ ('antifraud.events' / 'inspection.completed'), and exposes health probes.
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
from uuid import UUID, uuid4

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
    _fallback_req_id: ContextVar[Optional[str]] = ContextVar("scoring_req_id", default=None)

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

from .clients import DownstreamOrchestrator
from .config import settings
from .engine import evaluate_risk
from .publisher import RabbitMQPublisher
from .schemas import (
    HealthResponse,
    InspectionCompletedEvent,
    InspectionResult,
    ReadyResponse,
    SMSCheckRequest,
)

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

_orchestrator = DownstreamOrchestrator()
_publisher = RabbitMQPublisher()


def get_orchestrator() -> DownstreamOrchestrator:
    """FastAPI dependency providing the shared DownstreamOrchestrator."""
    return _orchestrator


def get_publisher() -> RabbitMQPublisher:
    """FastAPI dependency providing the shared RabbitMQPublisher."""
    return _publisher


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Starts pooled HTTP client and connects RabbitMQ publisher."""
    logger.info("Scoring Service starting up...")
    await _orchestrator.start()
    try:
        await _publisher.connect()
    except Exception as exc:
        logger.warning(
            "RabbitMQ initial connection failed (%s: %s); /ready will report 503 until connected",
            type(exc).__name__,
            exc,
        )

    yield

    logger.info("Scoring Service shutting down...")
    await _publisher.close()
    await _orchestrator.close()


app = FastAPI(
    title="Scoring Service",
    description=(
        "Core anti-fraud decision orchestrator aggregating Rule Engine, Reputation, "
        "and Velocity signals and publishing InspectionResult events to RabbitMQ."
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


def _resolve_request_uuid(request: Request) -> UUID:
    raw_id = _extract_request_id(request)
    if raw_id:
        try:
            return UUID(raw_id)
        except ValueError:
            pass
    return uuid4()


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
    logger.error("Unhandled exception during scoring request: %s", exc, exc_info=True)
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
    publisher: RabbitMQPublisher = Depends(get_publisher),
) -> ReadyResponse | JSONResponse:
    """Verifies active RabbitMQ publisher connection and declared exchange."""
    is_ready, error_detail = publisher.check_ready()
    if not is_ready:
        logger.warning("Readiness probe failed: %s", error_detail)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "error",
                "rabbitmq": "disconnected",
                "exchange": publisher.exchange_name,
                "service": settings.SERVICE_NAME,
                "detail": error_detail,
            },
        )
    return ReadyResponse(
        status="ready",
        rabbitmq="connected",
        exchange=publisher.exchange_name,
        service=settings.SERVICE_NAME,
    )


# ============================================================================
# Business Endpoints
# ============================================================================

@app.post(
    "/api/v1/score",
    response_model=InspectionResult,
    tags=["Scoring"],
    summary="Evaluate SMS Authentication Traffic Risk",
)
async def score_sms_request(
    payload: SMSCheckRequest,
    request: Request,
    orchestrator: DownstreamOrchestrator = Depends(get_orchestrator),
    publisher: RabbitMQPublisher = Depends(get_publisher),
) -> InspectionResult:
    """
    Orchestrates synchronous parallel inspection across Rule Engine, Reputation,
    and Velocity services, calculates dynamic Risk Score [0.0..100.0],
    evaluates ALLOW/DENY (threshold >= 60.0), and publishes the completed
    InspectionResult event to RabbitMQ exchange 'antifraud.events'.
    """
    start_time = time.perf_counter()
    request_uuid = _resolve_request_uuid(request)
    correlation_id = _extract_request_id(request) or str(request_uuid)

    rules, reputation, velocity = await orchestrator.gather_signals(
        payload=payload,
        request_id=correlation_id,
    )

    risk_score, verdict, reasons = evaluate_risk(
        rules=rules,
        reputation=reputation,
        velocity=velocity,
        deny_threshold=settings.DENY_THRESHOLD,
    )

    latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

    result = InspectionResult(
        request_id=request_uuid,
        verdict=verdict,
        risk_score=risk_score,
        reasons=reasons,
        latency_ms=latency_ms,
    )

    event = InspectionCompletedEvent(
        request_id=result.request_id,
        client_ip=payload.client_ip,
        phone_number=payload.phone_number,
        mcc_mnc=payload.mcc_mnc,
        verdict=result.verdict,
        risk_score=result.risk_score,
        reasons=result.reasons,
        latency_ms=result.latency_ms,
    )
    await publisher.publish_inspection_completed(event)

    logger.info(
        "Scoring completed: verdict=%s risk_score=%.2f reasons=%d latency_ms=%.2f",
        result.verdict.value,
        result.risk_score,
        len(result.reasons),
        result.latency_ms,
    )
    return result
