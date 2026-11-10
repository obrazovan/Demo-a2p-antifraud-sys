"""
Async SQLAlchemy engine, session lifecycle, and DB readiness checks for Reputation Service.
"""

from __future__ import annotations

from typing import AsyncGenerator, Optional
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import settings
from .models import Base, BlacklistedEntity

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
)

async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency yielding an isolated async database session."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Creates reputation tables if they do not yet exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def check_database_ready() -> tuple[bool, int, Optional[str]]:
    """
    Executes connectivity probe against PostgreSQL and counts blacklisted records.
    Returns: (is_healthy, blacklisted_count, error_detail)
    """
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
            count_stmt = select(func.count(BlacklistedEntity.id))
            result = await session.execute(count_stmt)
            total = result.scalar_one_or_none() or 0
            return True, int(total), None
    except Exception as exc:
        return False, 0, str(exc)
