"""
Pydantic v2 schemas for the Analytics Ingestion & Reporting Service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class IncomingInspectionEvent(BaseModel):
    """
    Event payload consumed from RabbitMQ queue 'analytics.raw_events'.
    Accepts InspectionCompletedEvent published by Scoring Service.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    event_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        validation_alias=AliasChoices("event_time", "timestamp"),
        description="Inspection event timestamp (UTC)",
    )
    request_id: UUID = Field(..., description="Unique request correlation UUID")
    client_ip: str = Field(default="0.0.0.0", description="Originating client IP")
    destination_phone: str = Field(
        default="",
        validation_alias=AliasChoices("destination_phone", "phone_number"),
        description="Target destination phone number",
    )
    mcc_mnc: str = Field(default="", description="Mobile Country Code + Mobile Network Code")
    verdict: str = Field(..., description="Evaluation verdict: ALLOW or DENY")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score in [0.0, 100.0]")
    latency_ms: float = Field(..., ge=0.0, description="Scoring latency in milliseconds")
    reasons: list[str] = Field(default_factory=list, description="Triggered rule reasons")

    def to_clickhouse_row(self) -> list[object]:
        """Converts event into ordered ClickHouse column row tuple/list."""
        # ClickHouse DateTime expects naive UTC datetime (seconds precision)
        dt = self.event_time
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return [
            dt,
            self.request_id,
            self.client_ip,
            self.destination_phone,
            self.mcc_mnc,
            self.verdict,
            float(self.risk_score),
            float(self.latency_ms),
            list(self.reasons),
        ]


class AnalyticsSummaryResponse(BaseModel):
    """Aggregated anti-fraud traffic statistics over the last hour."""
    window: str = Field(default="1h", description="Aggregation time window")
    total: int = Field(..., ge=0, description="Total SMS inspections in the last hour")
    blocked: int = Field(..., ge=0, description="Total DENY inspections in the last hour")
    allowed: int = Field(..., ge=0, description="Total ALLOW inspections in the last hour")
    block_rate_pct: float = Field(..., ge=0.0, le=100.0, description="Percentage of blocked traffic")
    avg_latency_ms: float = Field(..., ge=0.0, description="Average scoring latency in milliseconds")
    avg_risk_score: float = Field(..., ge=0.0, le=100.0, description="Average calculated risk score")


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-analytics")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response verifying ClickHouse connectivity."""
    status: str = Field(default="ready")
    clickhouse: str = Field(default="connected")
    database: str = Field(default="analytics_db")
    service: str = Field(default="service-analytics")
    consumer_connected: bool = Field(default=False)
    buffered_events: int = Field(default=0, ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
