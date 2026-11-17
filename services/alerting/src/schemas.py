"""
Pydantic v2 schemas for the Alerting & Security Audit Service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class AlertSeverity(str, Enum):
    """Security alert severity levels."""
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncomingInspectionEvent(BaseModel):
    """
    Event payload consumed from RabbitMQ queue 'security.alerts'.
    Matches InspectionCompletedEvent published by Scoring Service.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    event_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices("event_time", "timestamp"),
    )
    request_id: UUID
    client_ip: str = Field(default="0.0.0.0")
    phone_number: str = Field(
        default="",
        validation_alias=AliasChoices("phone_number", "destination_phone"),
    )
    mcc_mnc: str = Field(default="")
    verdict: str
    risk_score: float = Field(..., ge=0.0, le=100.0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    reasons: list[str] = Field(default_factory=list)


class SecurityAlertResponse(BaseModel):
    """Audited security alert returned by GET /api/v1/alerts."""
    id: int = Field(..., description="Monotonic audit record ID")
    alert_id: UUID = Field(..., description="Unique alert identifier")
    request_id: UUID = Field(..., description="Correlated inspection request ID")
    severity: AlertSeverity = Field(..., description="Alert severity: HIGH or CRITICAL")
    verdict: str = Field(..., description="Evaluation verdict")
    risk_score: float = Field(..., ge=0.0, le=100.0)
    client_ip: str
    phone_number: str
    mcc_mnc: str
    reasons: list[str] = Field(default_factory=list)
    cef_message: str = Field(..., description="Common Event Format (CEF:0) audit line")
    created_at: datetime = Field(..., description="Alert creation timestamp (UTC)")


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-alerting")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response verifying audit DB and RabbitMQ consumer status."""
    status: str = Field(default="ready")
    database: str = Field(default="connected")
    rabbitmq: str = Field(default="connected")
    alerts_stored: int = Field(default=0, ge=0)
    service: str = Field(default="service-alerting")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
