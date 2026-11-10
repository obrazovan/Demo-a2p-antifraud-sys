"""
SQLAlchemy 2.0 declarative database models for Reputation Service.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy models."""
    pass


class EntityType(str, Enum):
    """Entity types tracked by the threat reputation blacklist."""
    IP = "IP"
    PHONE = "PHONE"
    MCC_MNC = "MCC_MNC"


class BlacklistedEntity(Base):
    """Persistent blacklist record for malicious IPs, phones, or MCC/MNC ranges."""
    __tablename__ = "blacklisted_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_val", name="uq_entity"),
        Index("idx_entity_lookup", "entity_type", "entity_val"),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        doc="Unique blacklist record identifier",
    )
    entity_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
        doc="Entity category: IP, PHONE, or MCC_MNC",
    )
    entity_val: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Blacklisted entity value",
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Threat intelligence rationale for blacklisting",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Record creation timestamp (UTC)",
    )

    def __repr__(self) -> str:
        return (
            f"<BlacklistedEntity id={self.id} "
            f"type={self.entity_type} val={self.entity_val!r}>"
        )
