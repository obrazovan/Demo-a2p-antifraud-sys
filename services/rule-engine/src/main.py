"""
FastAPI application entrypoint for Rule Engine Service.
Exposes endpoints for rule retrieval, creation, and health checks.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator
from uuid import uuid4

# Ensure project root is available for shared package imports
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from shared.logger import get_logger, request_context, set_request_id
except ImportError:
    import logging
    from contextlib import contextmanager

    def get_logger(service_name: str, level: str = "INFO") -> logging.Logger:
        return logging.getLogger(service_name)

    def set_request_id(req_id: str | None) -> None:
        pass

    @contextmanager
    def request_context(req_id: str):
        yield

from .config import settings
from .crud import (
    create_rule,
    get_active_rules,
    get_rule_by_name,
    seed_default_rules_if_empty,
)
from .database import async_session_maker, check_database_ready, get_db, init_db
from .schemas import HealthResponse, ReadyResponse, RuleCreate, RuleResponse

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle manager."""
    logger.info("Rule Engine Service starting up...")
    try:
        # Initialize database schema
        await init_db()
        logger.info("Database schema verified/created.")

        # Seed default heuristics if empty
        async with async_session_maker() as session:
            await seed_default_rules_if_empty(session)
    except Exception as exc:
        logger.error(f"Startup initialization warning/error: {exc}")

    yield

    logger.info("Rule Engine Service shutting down...")


app = FastAPI(
    title="Rule Engine Service",
    description="Manages fraud scoring heuristics, rule definitions, and thresholds.",
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Middlewares
# ============================================================================

@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    """Injects X-Request-ID and structured logging for incoming HTTP requests."""
    request_id = request.headers.get("X-Request-ID") or str(uuid4())
    set_request_id(request_id)

    with request_context(request_id):
        logger.info(f"Incoming {request.method} {request.url.path}")
        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        logger.info(f"Completed {request.method} {request.url.path} with status {response.status_code}")
        return response


# ============================================================================
# Exception Handlers (Standardized Error Envelopes - No stack leaks)
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": "HTTP_ERROR",
            "message": exc.detail,
            "request_id": request_id,
            "details": None,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error_code": "VALIDATION_ERROR",
            "message": "Input validation error",
            "request_id": request_id,
            "details": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
async def readiness_check() -> ReadyResponse:
    """Verifies Postgres database connectivity and rules availability."""
    is_ready, count, error_detail = await check_database_ready()
    if not is_ready:
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
        rules_count=count,
    )


# ============================================================================
# Business Endpoints
# ============================================================================

@app.get(
    "/api/v1/rules",
    response_model=list[RuleResponse],
    tags=["Rules"],
    summary="Retrieve Active Scoring Rules",
)
async def list_active_rules(
    db: AsyncSession = Depends(get_db),
) -> list[RuleResponse]:
    """Returns list of all active fraud scoring heuristics."""
    rules = await get_active_rules(db)
    return [RuleResponse.model_validate(r) for r in rules]


@app.post(
    "/api/v1/rules",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Rules"],
    summary="Create New Scoring Rule",
)
async def add_rule(
    rule_in: RuleCreate,
    db: AsyncSession = Depends(get_db),
) -> RuleResponse:
    """Defines and registers a new fraud scoring heuristic."""
    # Check for name uniqueness
    existing = await get_rule_by_name(db, rule_in.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with name '{rule_in.name}' already exists",
        )

    try:
        new_rule = await create_rule(db, rule_in)
        return RuleResponse.model_validate(new_rule)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Database integrity conflict: {exc.orig}",
        )

