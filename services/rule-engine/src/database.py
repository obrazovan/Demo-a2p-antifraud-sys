"""
Database engine, session management, and connectivity helpers.
"""

from __future__ import annotations

from typing import AsyncGenerator, Optional
from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import settings
from .models import Base, Rule

# Create async engine with connection pooling
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
)

# Async session factory
async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency yielding an isolated async SQLAlchemy session."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Creates all database tables defined in metadata if they do not exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def check_database_ready() -> tuple[bool, int, Optional[str]]:
    """
    Executes a ping check and counts active rules.
    Returns: (is_healthy, active_rules_count, error_detail)
    """
    try:
        async with async_session_maker() as session:
            # 1. Connectivity test
            await session.execute(text("SELECT 1"))

            # 2. Query active rules count
            count_query = select(func.count(Rule.id)).where(Rule.is_active.is_(True))
            result = await session.execute(count_query)
            active_count = result.scalar_one_or_none() or 0
            return True, int(active_count), None
    except Exception as exc:
        return False, 0, str(exc)
