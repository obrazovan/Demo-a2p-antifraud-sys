"""
FastAPI application entrypoint for the Reputation Service.
Provides blacklist lookup, threat entity management, structured JSON logging,
and health/readiness probes backed by PostgreSQL (reputation_db).
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

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.logger import get_logger, request_context, set_request_id
except ImportError:
    _fallback_req_id: ContextVar[Optional[str]] = ContextVar("reputation_req_id", default=None)

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
from .crud import (
    add_entity_to_blacklist,
    check_entities_against_blacklist,
    get_blacklisted_entity,
    list_blacklisted_entities,
    seed_mock_bad_actors,
)
from .database import async_session_maker, check_database_ready, get_db, init_db
from .models import EntityType
from .schemas import (
    BlacklistCreateRequest,
    BlacklistedEntityResponse,
    HealthResponse,
    MatchedEntityDetail,
    ReadyResponse,
    ReputationCheckRequest,
    ReputationCheckResponse,
)

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle manager."""
    logger.info("Reputation Service starting up...")
    try:
        await init_db()
        logger.info("Reputation database schema verified/created.")

        async with async_session_maker() as session:
            await seed_mock_bad_actors(session)
    except Exception as exc:
        logger.error("Startup initialization warning/error: %s", exc, exc_info=True)

    yield

    logger.info("Reputation Service shutting down...")


app = FastAPI(
    title="Reputation Service",
    description="Manages threat blacklists and evaluates IP, Phone, and MCC/MNC reputation.",
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Middlewares
# ============================================================================

@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    """
    Extracts X-Request-ID from incoming headers (or generates UUID4),
    binds it to structured JSON log context, and returns it in response headers.
    """
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
    logger.error("Unhandled exception during request processing: %s", exc, exc_info=True)
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
    """Immediate liveness check returning HTTP 200 if process is responsive."""
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
async def readiness_check() -> ReadyResponse | JSONResponse:
    """Verifies PostgreSQL connectivity (reputation_db) and counts blacklisted entries."""
    is_ready, count, error_detail = await check_database_ready()
    if not is_ready:
        logger.warning("Readiness probe failed: %s", error_detail)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "error",
                "database": "disconnected",
                "service": settings.SERVICE_NAME,
                "detail": error_detail,
            },
        )
    return ReadyResponse(
        status="ready",
        database="connected",
        service=settings.SERVICE_NAME,
        blacklisted_count=count,
    )


# ============================================================================
# Business Endpoints
# ============================================================================

@app.post(
    "/api/v1/reputation/check",
    response_model=ReputationCheckResponse,
    tags=["Reputation"],
    summary="Check Entities Against Threat Blacklist",
)
async def check_reputation(
    payload: ReputationCheckRequest,
    db: AsyncSession = Depends(get_db),
) -> ReputationCheckResponse:
    """
    Evaluates submitted entities (ip, phone, mcc_mnc, or explicit entities list)
    against the blacklist database and returns matches with full metadata.
    """
    matches, checked_count = await check_entities_against_blacklist(db, payload)
    matched_details = [
        MatchedEntityDetail(
            id=record.id,
            type=EntityType(record.entity_type),
            value=record.entity_val,
            reason=record.reason,
            created_at=record.created_at,
        )
        for record in matches
    ]

    is_blacklisted = len(matched_details) > 0
    logger.info(
        "Reputation check completed: checked=%d matched=%d blacklisted=%s",
        checked_count,
        len(matched_details),
        is_blacklisted,
    )
    return ReputationCheckResponse(
        is_blacklisted=is_blacklisted,
        matched_entities=matched_details,
        checked_entities_count=checked_count,
    )


@app.post(
    "/api/v1/reputation/blacklist",
    response_model=BlacklistedEntityResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Reputation"],
    summary="Add Entity to Blacklist",
)
async def add_to_blacklist(
    payload: BlacklistCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> BlacklistedEntityResponse:
    """Adds a malicious IP, phone number, or MCC/MNC range to the blacklist."""
    existing = await get_blacklisted_entity(
        db,
        EntityType(payload.entity_type.value),
        payload.entity_val,
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{payload.entity_type.value} '{payload.entity_val}' is already blacklisted",
        )

    try:
        record = await add_entity_to_blacklist(db, payload)
        logger.info(
            "Added entity to blacklist: type=%s val=%s id=%d",
            record.entity_type,
            record.entity_val,
            record.id,
        )
        return BlacklistedEntityResponse.model_validate(record)
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{payload.entity_type.value} '{payload.entity_val}' is already blacklisted",
        )


@app.get(
    "/api/v1/reputation/blacklist",
    response_model=list[BlacklistedEntityResponse],
    tags=["Reputation"],
    summary="List Blacklisted Entities",
)
async def get_blacklist(
    entity_type: Optional[EntityType] = Query(
        default=None,
        description="Filter blacklist records by entity type",
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> list[BlacklistedEntityResponse]:
    """Lists blacklisted entities with optional entity_type filtering and pagination."""
    model_type = EntityType(entity_type.value) if entity_type is not None else None
    records = await list_blacklisted_entities(
        db,
        entity_type=model_type,
        limit=limit,
        offset=offset,
    )
    return [BlacklistedEntityResponse.model_validate(r) for r in records]
