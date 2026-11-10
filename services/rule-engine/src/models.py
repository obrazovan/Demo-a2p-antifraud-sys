"""
SQLAlchemy 2.0 declarative database models for Rule Engine Service.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from sqlalchemy import Boolean, DateTime, Float, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy models."""
    pass


class MetricType(str, Enum):
    """Categorization of fraud detection heuristics."""
    VELOCITY = "VELOCITY"
    REPUTATION = "REPUTATION"
    GEO = "GEO"


class Rule(Base):
    """Fraud scoring rule definition model."""
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        doc="Unique rule identifier",
    )
    name: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
        doc="Human-readable unique rule name / identifier",
    )
    metric_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="Metric domain: VELOCITY, REPUTATION, or GEO",
    )
    threshold_val: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        doc="Numerical trigger boundary for heuristic",
    )
    weight: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=10.0,
        doc="Risk score penalty added when rule triggers",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        doc="Whether this rule participates in active scoring evaluations",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Record creation timestamp (UTC)",
    )

    def __repr__(self) -> str:
        return f"<Rule id={self.id} name={self.name!r} type={self.metric_type} weight={self.weight}>"

