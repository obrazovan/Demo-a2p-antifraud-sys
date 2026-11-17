"""
ClickHouse OLAP storage adapter using clickhouse-connect.
Manages DDL initialization for `sms_inspections`, batch inserts,
last-hour aggregate queries, and readiness verification.
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any, Optional, Sequence

import clickhouse_connect

from .config import settings
from .schemas import AnalyticsSummaryResponse

logger = logging.getLogger(settings.SERVICE_NAME)

SMS_INSPECTIONS_COLUMNS: list[str] = [
    "event_time",
    "request_id",
    "client_ip",
    "destination_phone",
    "mcc_mnc",
    "verdict",
    "risk_score",
    "latency_ms",
    "reasons",
]


def _safe_float(value: Any, decimals: int = 2) -> float:
    """Safely normalizes ClickHouse numeric aggregates (guarding against None/NaN/Inf)."""
    if value is None:
        return 0.0
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(numeric):
        return 0.0
    return round(numeric, decimals)


class ClickHouseStorage:
    """Async-friendly wrapper around clickhouse-connect Client."""

    def __init__(
        self,
        host: str = settings.CLICKHOUSE_HOST,
        port: int = settings.CLICKHOUSE_PORT,
        database: str = settings.CLICKHOUSE_DB,
        username: str = settings.CLICKHOUSE_USER,
        password: str = settings.CLICKHOUSE_PASSWORD,
        client: Any = None,
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self._client: Any = client
        self._owns_client: bool = client is None
        self._io_lock = asyncio.Lock()

    def _create_client_sync(self) -> Any:
        # First connect without database so we can ensure database exists
        bootstrap = clickhouse_connect.get_client(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            connect_timeout=settings.CLICKHOUSE_CONNECT_TIMEOUT,
            send_receive_timeout=settings.CLICKHOUSE_SEND_RECEIVE_TIMEOUT,
        )
        try:
            bootstrap.command(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        finally:
            bootstrap.close()

        return clickhouse_connect.get_client(
            host=self.host,
            port=self.port,
            database=self.database,
            username=self.username,
            password=self.password,
            connect_timeout=settings.CLICKHOUSE_CONNECT_TIMEOUT,
            send_receive_timeout=settings.CLICKHOUSE_SEND_RECEIVE_TIMEOUT,
        )

    def _ensure_schema_sync(self) -> None:
        ddl = f"""
        CREATE TABLE IF NOT EXISTS {self.database}.sms_inspections (
            event_time DateTime DEFAULT now(),
            request_id UUID,
            client_ip String,
            destination_phone String,
            mcc_mnc LowCardinality(String),
            verdict LowCardinality(String),
            risk_score Float32,
            latency_ms Float32,
            reasons Array(String)
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(event_time)
        ORDER BY (event_time, verdict, mcc_mnc)
        """
        self._client.command(ddl)

    async def connect_and_init(self) -> None:
        """Connects to ClickHouse and ensures `analytics_db.sms_inspections` exists."""
        async with self._io_lock:
            if self._client is None:
                self._client = await asyncio.to_thread(self._create_client_sync)
                self._owns_client = True
            await asyncio.to_thread(self._ensure_schema_sync)
        logger.info(
            "ClickHouse connected and table '%s.sms_inspections' verified.",
            self.database,
        )

    async def close(self) -> None:
        """Closes owned ClickHouse HTTP client."""
        async with self._io_lock:
            if self._client is not None and self._owns_client:
                await asyncio.to_thread(self._client.close)
                self._client = None

    async def check_ready(self) -> tuple[bool, Optional[str]]:
        """Pings ClickHouse to confirm connectivity."""
        async with self._io_lock:
            if self._client is None:
                try:
                    self._client = await asyncio.to_thread(self._create_client_sync)
                    self._owns_client = True
                    await asyncio.to_thread(self._ensure_schema_sync)
                except Exception as exc:
                    return False, str(exc)

            try:
                ok = await asyncio.to_thread(self._client.ping)
                if ok:
                    return True, None
                return False, "ClickHouse ping returned falsy result"
            except Exception as exc:
                return False, str(exc)

    async def insert_batch(self, rows: Sequence[Sequence[object]]) -> int:
        """Executes a single batch INSERT into `sms_inspections`."""
        if not rows:
            return 0
        async with self._io_lock:
            if self._client is None:
                raise RuntimeError("ClickHouse client is not connected")
            await asyncio.to_thread(
                self._client.insert,
                f"{self.database}.sms_inspections",
                rows,
                column_names=SMS_INSPECTIONS_COLUMNS,
            )
        return len(rows)

    async def get_last_hour_summary(self) -> AnalyticsSummaryResponse:
        """Aggregates total, blocked, allowed, and average latency over the last 1 hour."""
        query = f"""
        SELECT
            count() AS total,
            countIf(verdict = 'DENY') AS blocked,
            countIf(verdict = 'ALLOW') AS allowed,
            coalesce(avgOrNull(latency_ms), 0.0) AS avg_latency_ms,
            coalesce(avgOrNull(risk_score), 0.0) AS avg_risk_score
        FROM {self.database}.sms_inspections
        WHERE event_time >= now() - INTERVAL 1 HOUR
        """
        async with self._io_lock:
            if self._client is None:
                raise RuntimeError("ClickHouse client is not connected")
            result = await asyncio.to_thread(self._client.query, query)

        rows = getattr(result, "result_rows", None) or []
        if not rows:
            return AnalyticsSummaryResponse(
                window="1h",
                total=0,
                blocked=0,
                allowed=0,
                block_rate_pct=0.0,
                avg_latency_ms=0.0,
                avg_risk_score=0.0,
            )

        total, blocked, allowed, avg_latency, avg_risk = rows[0]
        total_int = int(total or 0)
        blocked_int = int(blocked or 0)
        allowed_int = int(allowed or 0)
        block_rate = round((blocked_int / total_int) * 100.0, 2) if total_int > 0 else 0.0

        return AnalyticsSummaryResponse(
            window="1h",
            total=total_int,
            blocked=blocked_int,
            allowed=allowed_int,
            block_rate_pct=block_rate,
            avg_latency_ms=_safe_float(avg_latency, 2),
            avg_risk_score=_safe_float(avg_risk, 2),
        )
