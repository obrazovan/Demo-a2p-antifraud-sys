"""
Async HTTP orchestration client for downstream anti-fraud microservices
(Rule Engine, Reputation Service, and Velocity Service) using httpx.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

from .config import settings
from .schemas import (
    ActiveRule,
    ReputationLookupResult,
    SMSCheckRequest,
    VelocityLookupResult,
)

logger = logging.getLogger(settings.SERVICE_NAME)

FALLBACK_DEFAULT_RULES: list[ActiveRule] = [
    ActiveRule(
        id=1,
        name="High velocity IP (>10 req/min)",
        metric_type="VELOCITY",
        threshold_val=10.0,
        weight=40.0,
        is_active=True,
    ),
    ActiveRule(
        id=2,
        name="High velocity Destination (>30 req/min)",
        metric_type="VELOCITY",
        threshold_val=30.0,
        weight=50.0,
        is_active=True,
    ),
    ActiveRule(
        id=3,
        name="Blacklisted prefix/IP",
        metric_type="REPUTATION",
        threshold_val=0.0,
        weight=100.0,
        is_active=True,
    ),
]


class DownstreamOrchestrator:
    """
    Maintains a pooled httpx.AsyncClient, caches active Rule Engine weights with a TTL,
    and executes Reputation + Velocity checks in parallel with X-Request-ID forwarding.
    """

    def __init__(
        self,
        rule_engine_url: str = settings.RULE_ENGINE_URL,
        reputation_url: str = settings.REPUTATION_URL,
        velocity_url: str = settings.VELOCITY_URL,
        rules_cache_ttl: float = settings.RULES_CACHE_TTL_SECONDS,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.rule_engine_url = rule_engine_url.rstrip("/")
        self.reputation_url = reputation_url.rstrip("/")
        self.velocity_url = velocity_url.rstrip("/")
        self.rules_cache_ttl = rules_cache_ttl

        self._client: Optional[httpx.AsyncClient] = http_client
        self._owns_client: bool = http_client is None
        self._rules_cache: Optional[list[ActiveRule]] = None
        self._cache_expires_at: float = 0.0
        self._cache_lock = asyncio.Lock()

    async def start(self) -> None:
        """Initializes the pooled async HTTP client if not injected externally."""
        if self._client is None:
            timeout = httpx.Timeout(
                connect=settings.HTTP_CONNECT_TIMEOUT,
                read=settings.HTTP_READ_TIMEOUT,
                write=settings.HTTP_READ_TIMEOUT,
                pool=settings.HTTP_CONNECT_TIMEOUT,
            )
            limits = httpx.Limits(
                max_keepalive_connections=50,
                max_connections=100,
                keepalive_expiry=30.0,
            )
            self._client = httpx.AsyncClient(timeout=timeout, limits=limits)
            self._owns_client = True

    async def close(self) -> None:
        """Closes the owned async HTTP client pool."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def invalidate_rules_cache(self) -> None:
        """Clears cached rules so the next call fetches fresh weights."""
        self._rules_cache = None
        self._cache_expires_at = 0.0

    async def get_active_rules(self, request_id: str) -> list[ActiveRule]:
        """
        Returns active scoring rules from TTL cache or fetches them from Rule Engine.
        Falls back to stale cache or built-in defaults if Rule Engine is unreachable.
        """
        now = time.monotonic()
        if self._rules_cache is not None and now < self._cache_expires_at:
            return self._rules_cache

        async with self._cache_lock:
            # Double-check after acquiring lock
            now = time.monotonic()
            if self._rules_cache is not None and now < self._cache_expires_at:
                return self._rules_cache

            if self._client is None:
                logger.warning("HTTP client not initialized; using fallback rules")
                return self._rules_cache or list(FALLBACK_DEFAULT_RULES)

            try:
                resp = await self._client.get(
                    f"{self.rule_engine_url}/api/v1/rules",
                    headers={"X-Request-ID": request_id},
                )
                resp.raise_for_status()
                raw_rules = resp.json()
                parsed = [ActiveRule.model_validate(item) for item in raw_rules]
                self._rules_cache = parsed
                self._cache_expires_at = time.monotonic() + self.rules_cache_ttl
                return parsed
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "Rule Engine request failed (%s: %s); using fallback rules",
                    type(exc).__name__,
                    exc,
                )
                if self._rules_cache is not None:
                    return self._rules_cache
                return list(FALLBACK_DEFAULT_RULES)

    async def check_reputation(
        self,
        payload: SMSCheckRequest,
        request_id: str,
    ) -> ReputationLookupResult:
        """Queries Reputation Service for blacklist hits across IP, phone, and MCC/MNC."""
        if self._client is None:
            logger.warning("HTTP client not initialized; skipping reputation lookup")
            return ReputationLookupResult()

        try:
            resp = await self._client.post(
                f"{self.reputation_url}/api/v1/reputation/check",
                headers={"X-Request-ID": request_id},
                json={
                    "ip": payload.client_ip,
                    "phone": payload.phone_number,
                    "mcc_mnc": payload.mcc_mnc,
                },
            )
            resp.raise_for_status()
            return ReputationLookupResult.model_validate(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "Reputation Service request failed (%s: %s); falling back to clean result",
                type(exc).__name__,
                exc,
            )
            return ReputationLookupResult()

    async def record_velocity(
        self,
        payload: SMSCheckRequest,
        request_id: str,
    ) -> VelocityLookupResult:
        """Registers the hit in Velocity Service and retrieves sliding-window counts."""
        if self._client is None:
            logger.warning("HTTP client not initialized; skipping velocity lookup")
            return VelocityLookupResult()

        try:
            resp = await self._client.post(
                f"{self.velocity_url}/api/v1/velocity/hit",
                headers={"X-Request-ID": request_id},
                json={
                    "ip": payload.client_ip,
                    "phone": payload.phone_number,
                },
            )
            resp.raise_for_status()
            return VelocityLookupResult.model_validate(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "Velocity Service request failed (%s: %s); falling back to zero counts",
                type(exc).__name__,
                exc,
            )
            return VelocityLookupResult()

    async def gather_signals(
        self,
        payload: SMSCheckRequest,
        request_id: str,
    ) -> tuple[list[ActiveRule], ReputationLookupResult, VelocityLookupResult]:
        """
        Orchestrates Rule Engine, Reputation Service, and Velocity Service calls
        concurrently to minimize end-to-end scoring latency.
        """
        rules, reputation, velocity = await asyncio.gather(
            self.get_active_rules(request_id),
            self.check_reputation(payload, request_id),
            self.record_velocity(payload, request_id),
        )
        return rules, reputation, velocity
