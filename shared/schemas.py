"""
Shared Pydantic schemas, DTOs, and structured logging utilities
for the Anti-Fraud Microservice Platform.
"""

from __future__ import annotations

import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Enums
# ============================================================================

class Verdict(str, Enum):
    """Fraud decision verdict."""
    ALLOW = "ALLOW"
    DENY = "DENY"


class EntityType(str, Enum):
    """Entities subject to reputation checks."""
    IP = "IP"
    PHONE = "PHONE"
    MCC_MNC = "MCC_MNC"


# ============================================================================
# Ingress & Core DTOs
# ============================================================================

class SMSCheckRequest(BaseModel):
    """Ingress request model for SMS authentication traffic inspection."""
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "client_ip": "198.51.100.24",
                "phone_number": "+24101234567",
                "mcc_mnc": "62801",
                "timestamp": "2026-11-09T20:15:30.123Z",
                "message_length": 24,
                "sender_id": "AUTH_VERIFY",
            }
        },
    )

    client_ip: str = Field(
        ...,
        description="IPv4 or IPv6 address of the originating client",
        min_length=7,
        max_length=45,
    )
    phone_number: str = Field(
        ...,
        description="E.164 formatted target phone number",
        min_length=7,
        max_length=20,
    )
    mcc_mnc: str = Field(
        ...,
        description="Mobile Country Code + Mobile Network Code (5 or 6 digits)",
        min_length=5,
        max_length=6,
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of request origination (UTC)",
    )
    message_length: int = Field(
        ...,
        ge=0,
        le=2000,
        description="Length of SMS text content in characters",
    )
    sender_id: Optional[str] = Field(
        default="AUTH_VERIFY",
        max_length=32,
        description="Alphanumeric identifier of sending brand/service",
    )

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned.startswith("+"):
            raise ValueError("Phone number must begin with '+' (E.164 format)")
        if not cleaned[1:].isdigit():
            raise ValueError("Phone number must contain only numeric digits after '+'")
        return cleaned

    @field_validator("mcc_mnc")
    @classmethod
    def validate_mcc_mnc(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned.isdigit():
            raise ValueError("mcc_mnc must consist strictly of digits")
        return cleaned


class InspectionResult(BaseModel):
    """Standardized decision outcome produced by the Scoring Engine."""
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
                "verdict": "DENY",
                "risk_score": 85.0,
                "reasons": [
                    "REPUTATION_BLACKLIST_MATCH: IP 198.51.100.24",
                    "VELOCITY_LIMIT_EXCEEDED: IP frequency > 10/min",
                ],
                "latency_ms": 4.12,
            }
        },
    )

    request_id: UUID = Field(
        default_factory=uuid4,
        description="Unique request tracing identifier",
    )
    verdict: Verdict = Field(
        ...,
        description="Final evaluation decision: ALLOW or DENY",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated fraud probability score in range [0.0, 100.0]",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="List of triggered heuristics, velocity spikes, or blacklist matches",
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Total synchronous evaluation latency in milliseconds",
    )


# Alias for backward compatibility with external API responses
InspectionResponse = InspectionResult


# ============================================================================
# Inter-Service Communication DTOs
# ============================================================================

class MatchedEntity(BaseModel):
    """Blacklist match descriptor."""
    type: str = Field(..., description="Matched entity type (IP, PHONE, MCC_MNC)")
    value: str = Field(..., description="Value that matched blacklist")
    reason: str = Field(..., description="Blacklisting cause/category")


class ReputationCheckRequest(BaseModel):
    """Payload sent to Reputation Service."""
    ip: str = Field(..., description="Client IP to check")
    phone: str = Field(..., description="Target phone number")
    mcc_mnc: str = Field(..., description="MCC/MNC identifier")


class ReputationCheckResponse(BaseModel):
    """Response returned by Reputation Service."""
    is_blacklisted: bool = Field(..., description="True if any entity is blacklisted")
    matched_entities: list[MatchedEntity] = Field(
        default_factory=list,
        description="Detailed blacklist hits",
    )


class VelocityHitRequest(BaseModel):
    """Payload sent to Velocity Service."""
    ip: str = Field(..., description="Client IP")
    phone: str = Field(..., description="Target phone number")


class VelocityHitResponse(BaseModel):
    """Response returned by Velocity Service."""
    ip_count_1m: int = Field(..., ge=0, description="Hit count for IP over last 60 seconds")
    phone_count_5m: int = Field(..., ge=0, description="Hit count for Phone over last 300 seconds")


class RuleDefinition(BaseModel):
    """Rule entity representation from Rule Engine Service."""
    id: Optional[int] = None
    rule_code: str
    description: Optional[str] = None
    threshold_value: float = 0.0
    weight: float = 10.0
    is_active: bool = True
    created_at: Optional[datetime] = None


class InspectionCompletedEvent(BaseModel):
    """Asynchronous RabbitMQ event published to 'antifraud' exchange."""
    event_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    client_ip: str
    phone_number: str
    mcc_mnc: str
    verdict: Verdict
    risk_score: float
    reasons: list[str] = Field(default_factory=list)
    latency_ms: float


class ErrorEnvelope(BaseModel):
    """Standardized error envelope preventing stack trace leaks."""
    error_code: str = Field(..., description="Machine-readable error category")
    message: str = Field(..., description="Human-readable explanation")
    request_id: Optional[str] = Field(default=None, description="Correlation request ID")
    details: Optional[Any] = Field(default=None, description="Optional diagnostic details")


class HealthStatus(BaseModel):
    """Service health response."""
    status: str = Field(default="ok")
    service: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Structured Logging Utility & Formatter
# ============================================================================

request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id_ctx", default=None)


class LogEntry(BaseModel):
    """Structured JSON log entry schema."""
    timestamp: str
    service: str
    level: str
    request_id: Optional[str] = None
    message: str


class CommonJSONFormatter(logging.Formatter):
    """
    Structured Logging Formatter returning single-line JSON with keys:
    - timestamp (ISO 8601 UTC)
    - service
    - level
    - request_id
    - message
    """

    def __init__(
        self,
        service_name: str = "antifraud-service",
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
    ):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        # Determine correlation request_id
        req_id = getattr(record, "request_id", None)
        if req_id is None:
            req_id = request_id_ctx.get()

        # Format ISO 8601 UTC timestamp with millisecond precision
        record_dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        timestamp_str = record_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        payload: dict[str, Any] = {
            "timestamp": timestamp_str,
            "service": getattr(record, "service", self.service_name),
            "level": record.levelname,
            "request_id": str(req_id) if req_id is not None else None,
            "message": record.getMessage(),
        }

        # Include stack trace if exception is attached
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Include optional extra context dictionary if present
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            payload.update(record.extra_fields)

        return json.dumps(payload, ensure_ascii=False)


def setup_structured_logging(
    service_name: str,
    level: str = "INFO",
) -> logging.Logger:
    """
    Configures the root or service logger to output structured JSON logs to stdout.
    """
    logger = logging.getLogger(service_name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Clear existing handlers to prevent duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(CommonJSONFormatter(service_name=service_name))
    logger.addHandler(handler)

    return logger

