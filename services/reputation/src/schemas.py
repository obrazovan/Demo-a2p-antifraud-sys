"""
Pydantic v2 request and response schemas for the Reputation Service.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import EntityType


class EntityCheckItem(BaseModel):
    """Explicit (entity_type, entity_val) lookup item."""
    entity_type: EntityType
    entity_val: str = Field(..., min_length=1, max_length=64)


class ReputationCheckRequest(BaseModel):
    """
    Request payload for checking entities against the threat blacklist.
    Supports both direct fields (ip, phone, mcc_mnc) and/or an explicit entities list.
    """
    ip: Optional[str] = Field(
        default=None,
        max_length=45,
        description="Client IPv4 or IPv6 address to check",
        examples=["198.51.100.24"],
    )
    phone: Optional[str] = Field(
        default=None,
        max_length=20,
        description="Destination phone number in E.164 format",
        examples=["+24101234567"],
    )
    mcc_mnc: Optional[str] = Field(
        default=None,
        max_length=6,
        description="Mobile Country Code + Mobile Network Code",
        examples=["62801"],
    )
    entities: Optional[list[EntityCheckItem]] = Field(
        default=None,
        description="Optional additional list of entities to evaluate in batch",
    )

    @model_validator(mode="after")
    def ensure_at_least_one_entity(self) -> "ReputationCheckRequest":
        has_named = any(
            val is not None and val.strip() != ""
            for val in (self.ip, self.phone, self.mcc_mnc)
        )
        has_list = bool(self.entities)
        if not has_named and not has_list:
            raise ValueError(
                "At least one entity (ip, phone, mcc_mnc, or non-empty entities list) must be provided"
            )
        return self


class MatchedEntityDetail(BaseModel):
    """Matched blacklist hit with full persistence metadata."""
    id: int = Field(..., description="Database ID of the matched blacklist record")
    type: EntityType = Field(..., description="Matched entity type (IP, PHONE, MCC_MNC)")
    value: str = Field(..., description="Matched entity value")
    reason: str = Field(..., description="Reason the entity was blacklisted")
    created_at: datetime = Field(..., description="Timestamp when entity was blacklisted (UTC)")

    model_config = ConfigDict(from_attributes=True)


class ReputationCheckResponse(BaseModel):
    """Response returned by POST /api/v1/reputation/check."""
    is_blacklisted: bool = Field(..., description="True if one or more entities matched the blacklist")
    matched_entities: list[MatchedEntityDetail] = Field(
        default_factory=list,
        description="List of matched blacklist entries with metadata",
    )
    checked_entities_count: int = Field(
        default=0,
        ge=0,
        description="Number of unique entity criteria evaluated",
    )


class BlacklistCreateRequest(BaseModel):
    """Payload for adding a malicious entity to the blacklist."""
    entity_type: EntityType = Field(
        ...,
        description="Category of entity: IP, PHONE, or MCC_MNC",
        examples=[EntityType.IP],
    )
    entity_val: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Entity value to blacklist",
        examples=["198.51.100.24"],
    )
    reason: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Reason or threat source describing why this entity is blocked",
        examples=["Automated SMS pumping botnet node"],
    )

    @model_validator(mode="after")
    def validate_entity_value_format(self) -> "BlacklistCreateRequest":
        cleaned = self.entity_val.strip()
        if not cleaned:
            raise ValueError("entity_val cannot be blank")

        if self.entity_type == EntityType.IP:
            try:
                ipaddress.ip_address(cleaned)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address format: {cleaned!r}") from exc
        elif self.entity_type == EntityType.PHONE:
            digits = cleaned[1:] if cleaned.startswith("+") else cleaned
            if not digits.isdigit() or len(digits) < 6:
                raise ValueError("PHONE entity_val must be E.164 or numeric (at least 6 digits)")
        elif self.entity_type == EntityType.MCC_MNC:
            if not cleaned.isdigit() or not (3 <= len(cleaned) <= 6):
                raise ValueError("MCC_MNC entity_val must be a 3 to 6 digit numeric identifier")

        self.entity_val = cleaned
        self.reason = self.reason.strip()
        return self


class BlacklistedEntityResponse(BaseModel):
    """Persisted blacklist record representation."""
    id: int
    entity_type: EntityType
    entity_val: str
    reason: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "entity_type": "IP",
                "entity_val": "198.51.100.24",
                "reason": "Known Tor exit node / automated SMS pumping proxy",
                "created_at": "2026-11-10T20:15:30.000Z",
            }
        },
    )


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-reputation")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response including database connectivity verification."""
    status: str = Field(default="ready")
    database: str = Field(default="connected")
    service: str = Field(default="service-reputation")
    blacklisted_count: int = Field(..., description="Total blacklisted entities stored in DB")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
