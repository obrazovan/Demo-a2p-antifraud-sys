"""
Pydantic schemas for the Rule Engine Service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class MetricType(str, Enum):
    """Supported heuristic metric classifications."""
    VELOCITY = "VELOCITY"
    REPUTATION = "REPUTATION"
    GEO = "GEO"


class RuleBase(BaseModel):
    """Base schema attributes for a fraud rule."""
    name: str = Field(
        ...,
        min_length=2,
        max_length=128,
        description="Unique name or descriptor for the scoring heuristic",
        examples=["High velocity IP (>10 req/min)"],
    )
    metric_type: MetricType = Field(
        ...,
        description="Metric category: VELOCITY, REPUTATION, or GEO",
        examples=[MetricType.VELOCITY],
    )
    threshold_val: float = Field(
        default=0.0,
        ge=0.0,
        description="Quantitative boundary triggering this rule",
        examples=[10.0],
    )
    weight: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Fraud risk penalty points added to score",
        examples=[40.0],
    )
    is_active: bool = Field(
        default=True,
        description="Whether this rule is evaluated during scoring",
    )


class RuleCreate(RuleBase):
    """Payload for creating a new scoring rule."""
    pass


class RuleUpdate(BaseModel):
    """Payload for partial rule update."""
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    metric_type: Optional[MetricType] = None
    threshold_val: Optional[float] = Field(default=None, ge=0.0)
    weight: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    is_active: Optional[bool] = None


class RuleResponse(RuleBase):
    """Rule entity response model."""
    id: int = Field(..., description="Unique database ID")
    created_at: datetime = Field(..., description="Creation timestamp (UTC)")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "name": "High velocity IP (>10 req/min)",
                "metric_type": "VELOCITY",
                "threshold_val": 10.0,
                "weight": 40.0,
                "is_active": True,
                "created_at": "2026-11-09T20:15:30.000Z",
            }
        },
    )


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-rule-engine")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response including database connectivity check."""
    status: str = Field(default="ready")
    database: str = Field(default="connected")
    service: str = Field(default="service-rule-engine")
    rules_count: int = Field(..., description="Total active rules in database")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

