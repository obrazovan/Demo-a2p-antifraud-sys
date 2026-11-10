"""
CRUD, indexed blacklist lookup, and startup seeding for Reputation Service.
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import BlacklistedEntity, EntityType
from .schemas import BlacklistCreateRequest, ReputationCheckRequest

logger = logging.getLogger("service-reputation")

DEFAULT_MOCK_BAD_ACTORS: list[dict[str, str]] = [
    {
        "entity_type": EntityType.IP.value,
        "entity_val": "198.51.100.24",
        "reason": "Known Tor exit node / automated SMS pumping proxy",
    },
    {
        "entity_type": EntityType.MCC_MNC.value,
        "entity_val": "62801",
        "reason": "Gabon test range - high-risk AIT destination",
    },
]


def _collect_lookup_candidates(
    payload: ReputationCheckRequest,
) -> tuple[dict[str, set[str]], int]:
    """
    Normalizes and groups lookup candidates by EntityType.
    For MCC_MNC values longer than 3 digits, includes the 3-digit MCC prefix
    so country-level blacklists also match cleanly using the composite index.
    Returns: (grouped_values_by_type, unique_entity_count)
    """
    grouped: dict[str, set[str]] = {}
    unique_inputs: set[tuple[str, str]] = set()

    def _add(entity_type: str, raw_val: Optional[str]) -> None:
        if raw_val is None:
            return
        cleaned = raw_val.strip()
        if not cleaned:
            return
        unique_inputs.add((entity_type, cleaned))
        bucket = grouped.setdefault(entity_type, set())
        bucket.add(cleaned)
        if entity_type == EntityType.MCC_MNC.value and len(cleaned) > 3:
            bucket.add(cleaned[:3])

    _add(EntityType.IP.value, payload.ip)
    _add(EntityType.PHONE.value, payload.phone)
    _add(EntityType.MCC_MNC.value, payload.mcc_mnc)

    if payload.entities:
        for item in payload.entities:
            _add(item.entity_type.value, item.entity_val)

    return grouped, len(unique_inputs)


async def check_entities_against_blacklist(
    db: AsyncSession,
    payload: ReputationCheckRequest,
) -> tuple[Sequence[BlacklistedEntity], int]:
    """
    Queries PostgreSQL for any blacklisted matches among the submitted entities.
    Returns: (matched_records, checked_entities_count)
    """
    grouped, checked_count = _collect_lookup_candidates(payload)
    if not grouped:
        return [], 0

    conditions = [
        and_(
            BlacklistedEntity.entity_type == etype,
            BlacklistedEntity.entity_val.in_(sorted(values)),
        )
        for etype, values in grouped.items()
    ]

    stmt = (
        select(BlacklistedEntity)
        .where(or_(*conditions))
        .order_by(BlacklistedEntity.id.asc())
    )
    result = await db.execute(stmt)
    return result.scalars().all(), checked_count


async def get_blacklisted_entity(
    db: AsyncSession,
    entity_type: EntityType,
    entity_val: str,
) -> Optional[BlacklistedEntity]:
    """Fetches a specific blacklisted entity by (entity_type, entity_val)."""
    stmt = select(BlacklistedEntity).where(
        and_(
            BlacklistedEntity.entity_type == entity_type.value,
            BlacklistedEntity.entity_val == entity_val,
        )
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def list_blacklisted_entities(
    db: AsyncSession,
    entity_type: Optional[EntityType] = None,
    limit: int = 100,
    offset: int = 0,
) -> Sequence[BlacklistedEntity]:
    """Lists persisted blacklist entries with optional type filtering."""
    stmt = select(BlacklistedEntity)
    if entity_type is not None:
        stmt = stmt.where(BlacklistedEntity.entity_type == entity_type.value)
    stmt = stmt.order_by(BlacklistedEntity.id.asc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()


async def add_entity_to_blacklist(
    db: AsyncSession,
    payload: BlacklistCreateRequest,
) -> BlacklistedEntity:
    """Persists a new blacklisted entity record."""
    record = BlacklistedEntity(
        entity_type=payload.entity_type.value,
        entity_val=payload.entity_val,
        reason=payload.reason,
    )
    db.add(record)
    await db.flush()
    await db.refresh(record)
    return record


async def seed_mock_bad_actors(db: AsyncSession) -> list[BlacklistedEntity]:
    """
    Idempotently seeds required mock bad actors on startup if not already present:
    - IP: 198.51.100.24
    - MCC_MNC: 62801 (Gabon test range)
    """
    created: list[BlacklistedEntity] = []
    for actor in DEFAULT_MOCK_BAD_ACTORS:
        existing = await get_blacklisted_entity(
            db,
            EntityType(actor["entity_type"]),
            actor["entity_val"],
        )
        if existing is None:
            record = BlacklistedEntity(
                entity_type=actor["entity_type"],
                entity_val=actor["entity_val"],
                reason=actor["reason"],
            )
            db.add(record)
            created.append(record)

    if created:
        await db.commit()
        for record in created:
            await db.refresh(record)
        logger.info("Seeded %d mock bad actors into reputation_db.", len(created))
    else:
        logger.info("Default mock bad actors already exist in reputation_db.")

    return created
