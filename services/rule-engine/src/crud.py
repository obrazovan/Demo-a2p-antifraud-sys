"""
CRUD operations and database seeding for Rule Engine Service.
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import MetricType, Rule
from .schemas import RuleCreate

logger = logging.getLogger("service-rule-engine")

DEFAULT_SEED_RULES: list[dict] = [
    {
        "name": "High velocity IP (>10 req/min)",
        "metric_type": MetricType.VELOCITY.value,
        "threshold_val": 10.0,
        "weight": 40.0,
        "is_active": True,
    },
    {
        "name": "High velocity Destination (>30 req/min)",
        "metric_type": MetricType.VELOCITY.value,
        "threshold_val": 30.0,
        "weight": 50.0,
        "is_active": True,
    },
    {
        "name": "Blacklisted prefix/IP",
        "metric_type": MetricType.REPUTATION.value,
        "threshold_val": 0.0,
        "weight": 100.0,
        "is_active": True,
    },
]


async def get_active_rules(db: AsyncSession) -> Sequence[Rule]:
    """Retrieves all active fraud scoring rules ordered by ID."""
    stmt = (
        select(Rule)
        .where(Rule.is_active.is_(True))
        .order_by(Rule.id.asc())
    )
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_all_rules(db: AsyncSession) -> Sequence[Rule]:
    """Retrieves all rules regardless of active status."""
    stmt = select(Rule).order_by(Rule.id.asc())
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_rule_by_name(db: AsyncSession, name: str) -> Optional[Rule]:
    """Fetches a single rule by unique name."""
    stmt = select(Rule).where(Rule.name == name)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_rule_by_id(db: AsyncSession, rule_id: int) -> Optional[Rule]:
    """Fetches a rule by its primary key ID."""
    stmt = select(Rule).where(Rule.id == rule_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def create_rule(db: AsyncSession, rule_in: RuleCreate) -> Rule:
    """Inserts a new scoring rule into the database."""
    rule = Rule(
        name=rule_in.name,
        metric_type=rule_in.metric_type.value,
        threshold_val=rule_in.threshold_val,
        weight=rule_in.weight,
        is_active=rule_in.is_active,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


async def seed_default_rules_if_empty(db: AsyncSession) -> list[Rule]:
    """
    Checks if rules table is empty. If empty, populates default heuristics:
    1. High velocity IP (>10 req/min, weight: 40.0)
    2. High velocity Destination (>30 req/min, weight: 50.0)
    3. Blacklisted prefix/IP (weight: 100.0)
    """
    count_stmt = select(func.count(Rule.id))
    result = await db.execute(count_stmt)
    count = result.scalar_one_or_none() or 0

    if count > 0:
        logger.info(f"Database already contains {count} rules. Skipping auto-seeding.")
        return []

    logger.info("Rules table is empty. Auto-populating default heuristic rules...")
    created_rules: list[Rule] = []
    for item in DEFAULT_SEED_RULES:
        rule = Rule(
            name=item["name"],
            metric_type=item["metric_type"],
            threshold_val=item["threshold_val"],
            weight=item["weight"],
            is_active=item["is_active"],
        )
        db.add(rule)
        created_rules.append(rule)

    await db.commit()
    for rule in created_rules:
        await db.refresh(rule)

    logger.info(f"Successfully seeded {len(created_rules)} default rules.")
    return created_rules

