"""
Pydantic v2 request and response schemas for the Velocity Service.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


class VelocityHitRequest(BaseModel):
    """
    Request payload for recording a velocity event.
    Accepts either ('ip', 'phone') or ('client_ip', 'phone_number').
    """
    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "ip": "198.51.100.24",
                "phone": "+24101234567",
            }
        },
    )

    ip: str = Field(
        ...,
        validation_alias=AliasChoices("ip", "client_ip"),
        min_length=7,
        max_length=45,
        description="Originating client IPv4 or IPv6 address",
    )
    phone: str = Field(
        ...,
        validation_alias=AliasChoices("phone", "phone_number"),
        min_length=6,
        max_length=20,
        description="Target destination phone number",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: {cleaned!r}") from exc
        return cleaned

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = value.strip()
        digits = cleaned[1:] if cleaned.startswith("+") else cleaned
        if not digits.isdigit() or len(digits) < 6:
            raise ValueError("Phone number must be E.164 or numeric (at least 6 digits)")
        return cleaned


class VelocityHitResponse(BaseModel):
    """Sliding-window hit frequencies returned after recording an event."""
    ip_count_1m: int = Field(
        ...,
        ge=0,
        description="Number of requests from client_ip within the last 60 seconds",
    )
    phone_count_5m: int = Field(
        ...,
        ge=0,
        description="Number of requests targeting phone_number within the last 300 seconds",
    )


class HealthResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="ok")
    service: str = Field(default="service-velocity")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReadyResponse(BaseModel):
    """Readiness probe response verifying Redis connectivity."""
    status: str = Field(default="ready")
    redis: str = Field(default="connected")
    service: str = Field(default="service-velocity")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
