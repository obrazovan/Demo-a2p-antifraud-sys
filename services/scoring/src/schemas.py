"""
Pydantic v2 DTO schemas for the Scoring Service.
Reuses core shared contracts (SMSCheckRequest, InspectionResult, Verdict, InspectionCompletedEvent).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# Ensure repository root is available for shared package imports
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from shared.schemas import (  # noqa: E402
    InspectionCompletedEvent,
    InspectionResult,
    MatchedEntity,
    SMSCheckRequest,
    Verdict,
)


class ActiveRule(BaseModel):
    """Scoring heuristic returned by Rule Engine Service."""
    id: Optional[int] = None
    name: str
    metric_type: str
    threshold_val: float = 0.0
    weight: float = 0.0
    is_active: bool = True


class ReputationLookupResult(BaseModel):
    """Normalized response from Reputation Service."""
    is_blacklisted: bool = False
    matched_entities: list[MatchedEntity] = Field(default_factory=list)


class VelocityLookupResult(BaseModel):
    """Normalized response from Velocity Service."""
    ip_count_1m: int = 0
    phone_count_5m: int = 0


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-scoring")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response checking RabbitMQ publisher connectivity."""
    status: str = Field(default="ready")
    rabbitmq: str = Field(default="connected")
    exchange: str = Field(default="antifraud.events")
    service: str = Field(default="service-scoring")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


__all__ = [
    "ActiveRule",
    "HealthResponse",
    "InspectionCompletedEvent",
    "InspectionResult",
    "MatchedEntity",
    "ReadyResponse",
    "ReputationLookupResult",
    "SMSCheckRequest",
    "VelocityLookupResult",
    "Verdict",
]
