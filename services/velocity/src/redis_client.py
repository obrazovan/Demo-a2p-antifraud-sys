"""
Async Redis client management and atomic sliding-window frequency counters.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional
from uuid import uuid4

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from .config import settings

logger = logging.getLogger(settings.SERVICE_NAME)

_redis_client: Optional[aioredis.Redis] = None


def create_redis_client() -> aioredis.Redis:
    """Creates a configured redis.asyncio client with strict connect/read timeouts."""
    return aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
        socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
        retry_on_timeout=False,
    )


async def init_redis() -> aioredis.Redis:
    """Initializes the module-level async Redis client."""
    global _redis_client
    _redis_client = create_redis_client()
    return _redis_client


async def close_redis() -> None:
    """Closes the async Redis connection pool cleanly on shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


def get_redis_client() -> Optional[aioredis.Redis]:
    """FastAPI dependency returning the active Redis client instance."""
    return _redis_client


async def check_redis_ready(
    client: Optional[aioredis.Redis] = None,
) -> tuple[bool, Optional[str]]:
    """
    Pings Redis with a strict timeout to verify readiness.
    Returns: (is_ready, error_detail)
    """
    target = client or _redis_client
    if target is None:
        return False, "Redis client is not initialized"

    try:
        pong = await asyncio.wait_for(
            target.ping(),
            timeout=settings.REDIS_OPERATION_TIMEOUT,
        )
        if pong:
            return True, None
        return False, "Redis ping returned falsy response"
    except (RedisError, asyncio.TimeoutError, TimeoutError, ConnectionError, OSError) as exc:
        return False, str(exc)


async def record_velocity_hit(
    client: Optional[aioredis.Redis],
    ip: str,
    phone: str,
) -> tuple[int, int]:
    """
    Atomically updates and counts sliding-window hits for IP (60s) and phone (300s)
    using Redis Sorted Sets inside a single MULTI/EXEC pipeline.

    Falls back gracefully to (0, 0) with a warning log on Redis errors or timeouts.
    """
    if client is None:
        logger.warning(
            "Redis client unavailable; falling back to safe zero-count (0, 0)"
        )
        return 0, 0

    now_ms = int(time.time() * 1000)
    unique_member = f"{now_ms}:{uuid4().hex}"
    windows = [
        (f"ip:{ip}", settings.IP_WINDOW_SECONDS),
        (f"phone:{phone}", settings.PHONE_WINDOW_SECONDS),
    ]

    try:
        async with client.pipeline(transaction=True) as pipe:
            for key, window_sec in windows:
                cutoff_ms = now_ms - (window_sec * 1000)
                pipe.zremrangebyscore(key, "-inf", cutoff_ms)
                pipe.zadd(key, {unique_member: now_ms})
                pipe.zcard(key)
                pipe.expire(key, window_sec + 5)

            results = await asyncio.wait_for(
                pipe.execute(),
                timeout=settings.REDIS_OPERATION_TIMEOUT,
            )

        # Each window queues 4 commands -> ZCARD results are at indices 2 and 6
        ip_count_1m = int(results[2])
        phone_count_5m = int(results[6])
        return ip_count_1m, phone_count_5m
    except (RedisError, asyncio.TimeoutError, TimeoutError, ConnectionError, OSError) as exc:
        logger.warning(
            "Redis velocity hit error (%s: %s); falling back to safe zero-count (0, 0)",
            type(exc).__name__,
            exc,
        )
        return 0, 0
