"""
FastAPI API Gateway for the A2P Anti-Fraud Microservice Platform.
Single external ingress point providing:
  - X-Request-ID (UUID4) generation and downstream correlation propagation
  - Bearer API Key, X-API-Key, and HTTP Basic authentication
  - Routing to Scoring, Analytics, Rule Engine, Reputation, and Alerting services
  - Structured JSON logging and standardized ErrorEnvelope responses
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
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from shared.schemas import InspectionResult, SMSCheckRequest

try:
    from shared.logger import get_logger, request_context, set_request_id
except ImportError:
    _fallback_req_id: ContextVar[Optional[str]] = ContextVar("gateway_req_id", default=None)

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

from .auth import verify_client_auth
from .config import settings
from .proxy import GatewayProxyClient

logger = get_logger(settings.SERVICE_NAME, level=settings.LOG_LEVEL)
HTTP_422_STATUS = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)

_proxy = GatewayProxyClient()


def get_proxy() -> GatewayProxyClient:
    """FastAPI dependency returning the shared GatewayProxyClient."""
    return _proxy


class HealthResponse(BaseModel):
    status: str = Field(default="ok")
    service: str = Field(default=settings.SERVICE_NAME)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    status: str = Field(default="ready")
    service: str = Field(default=settings.SERVICE_NAME)
    downstreams: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Starts and cleanly closes the pooled gateway HTTP proxy client."""
    logger.info("API Gateway starting up on port %d...", settings.PORT)
    await _proxy.start()
    yield
    logger.info("API Gateway shutting down...")
    await _proxy.close()


app = FastAPI(
    title="A2P Anti-Fraud Platform API Gateway",
    description=(
        "Unified ingress gateway enforcing Bearer/Basic API key authentication, "
        "X-Request-ID correlation, and routing across anti-fraud microservices."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ============================================================================
# Middlewares
# ============================================================================

@app.middleware("http")
async def correlation_id_and_logging_middleware(request: Request, call_next):
    """Generates or preserves X-Request-ID (UUID4), logs structured JSON, and echoes header."""
    raw_header = request.headers.get("X-Request-ID")
    request_id = raw_header.strip() if raw_header and raw_header.strip() else str(uuid4())
    request.state.request_id = request_id
    set_request_id(request_id)

    start_time = time.perf_counter()
    with request_context(request_id):
        logger.info("Gateway ingress %s %s", request.method, request.url.path)
        response: Response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "Gateway egress %s %s status=%d latency_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        return response


# ============================================================================
# Exception Handlers (Standardized Error Envelopes - No stack leaks)
# ============================================================================

def _extract_request_id(request: Request) -> str:
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")
    return req_id if req_id else str(uuid4())


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    request_id = _extract_request_id(request)
    headers = dict(exc.headers) if exc.headers else {}
    headers["X-Request-ID"] = request_id
    error_code = "UNAUTHORIZED" if exc.status_code == status.HTTP_401_UNAUTHORIZED else "HTTP_ERROR"
    return JSONResponse(
        status_code=exc.status_code,
        headers=headers,
        content={
            "error_code": error_code,
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
        headers={"X-Request-ID": request_id},
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
    logger.error("Unhandled gateway exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        headers={"X-Request-ID": request_id},
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected gateway error occurred",
            "request_id": request_id,
            "details": None,
        },
    )


# ============================================================================
# Health & Readiness Endpoints (Public)
# ============================================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Liveness Probe",
)
async def health_check() -> HealthResponse:
    """Immediate liveness check returning HTTP 200."""
    return HealthResponse(status="ok", service=settings.SERVICE_NAME)


@app.get(
    "/ready",
    response_model=ReadyResponse,
    tags=["System"],
    summary="Readiness Probe",
)
async def readiness_check(
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> ReadyResponse | JSONResponse:
    """Verifies downstream service reachability (requires Scoring Service to be healthy)."""
    is_ready, downstreams = await proxy.check_downstreams_health()
    if not is_ready:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "error",
                "service": settings.SERVICE_NAME,
                "downstreams": downstreams,
            },
        )
    return ReadyResponse(
        status="ready",
        service=settings.SERVICE_NAME,
        downstreams=downstreams,
    )


# ============================================================================
# Protected Business Routes (Bearer API Key / X-API-Key / Basic Auth)
# ============================================================================

@app.post(
    "/api/v1/verify",
    response_model=InspectionResult,
    tags=["Verification"],
    summary="Inspect SMS Authentication Traffic",
)
async def verify_sms(
    payload: SMSCheckRequest,
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes verified SMS check request to Scoring Service (POST /api/v1/score)."""
    request_id = _extract_request_id(request)
    return await proxy.forward(
        method="POST",
        target_url=f"{proxy.scoring_url}/api/v1/score",
        request_id=request_id,
        body=payload.model_dump_json().encode("utf-8"),
        content_type="application/json",
    )


@app.get(
    "/api/v1/analytics/{subpath:path}",
    tags=["Analytics"],
    summary="Proxy Analytics Endpoints",
)
async def proxy_analytics(
    subpath: str,
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes /api/v1/analytics/* -> Analytics Service /api/v1/*."""
    request_id = _extract_request_id(request)
    cleaned = subpath.lstrip("/")
    target = f"{proxy.analytics_url}/api/v1/{cleaned}"
    return await proxy.proxy_fastapi_request(request, target, request_id)


@app.api_route(
    "/api/v1/rules",
    methods=["GET", "POST"],
    tags=["Rules"],
    summary="Proxy Rule Engine Collection Endpoints",
)
async def proxy_rules_root(
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes GET/POST /api/v1/rules -> Rule Engine Service /api/v1/rules."""
    request_id = _extract_request_id(request)
    target = f"{proxy.rule_engine_url}/api/v1/rules"
    return await proxy.proxy_fastapi_request(request, target, request_id)


@app.api_route(
    "/api/v1/rules/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    tags=["Rules"],
    summary="Proxy Rule Engine Subpath Endpoints",
)
async def proxy_rules_subpath(
    subpath: str,
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes /api/v1/rules/* -> Rule Engine Service /api/v1/rules/*."""
    request_id = _extract_request_id(request)
    cleaned = subpath.lstrip("/")
    target = f"{proxy.rule_engine_url}/api/v1/rules/{cleaned}"
    return await proxy.proxy_fastapi_request(request, target, request_id)


@app.get(
    "/api/v1/alerts",
    tags=["Alerts"],
    summary="Proxy Security Alerts Endpoint",
)
async def proxy_alerts(
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes GET /api/v1/alerts -> Alerting Service /api/v1/alerts."""
    request_id = _extract_request_id(request)
    target = f"{proxy.alerting_url}/api/v1/alerts"
    return await proxy.proxy_fastapi_request(request, target, request_id)


@app.api_route(
    "/api/v1/reputation/{subpath:path}",
    methods=["GET", "POST"],
    tags=["Reputation"],
    summary="Proxy Reputation Service Endpoints",
)
async def proxy_reputation(
    subpath: str,
    request: Request,
    _principal: str = Depends(verify_client_auth),
    proxy: GatewayProxyClient = Depends(get_proxy),
) -> Response:
    """Routes /api/v1/reputation/* -> Reputation Service /api/v1/reputation/*."""
    request_id = _extract_request_id(request)
    cleaned = subpath.lstrip("/")
    target = f"{proxy.reputation_url}/api/v1/reputation/{cleaned}"
    return await proxy.proxy_fastapi_request(request, target, request_id)
