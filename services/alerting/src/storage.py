"""
Async SQLite audit storage adapter for Security Alerts using aiosqlite.
Persists generated CEF alerts and serves recent audit history.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

import aiosqlite

from .config import settings
from .schemas import AlertSeverity, IncomingInspectionEvent, SecurityAlertResponse

logger = logging.getLogger(settings.SERVICE_NAME)


class AlertAuditStorage:
    """Async SQLite persistence layer for the security_alerts audit trail."""

    def __init__(self, db_path: str = settings.SQLITE_DB_PATH) -> None:
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def connect_and_init(self) -> None:
        """Opens SQLite connection and initializes the security_alerts audit table."""
        async with self._lock:
            if self.db_path != ":memory:":
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

            self._conn = await aiosqlite.connect(self.db_path)
            self._conn.row_factory = aiosqlite.Row

            if self.db_path != ":memory:":
                await self._conn.execute("PRAGMA journal_mode=WAL;")

            await self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    request_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    client_ip TEXT NOT NULL,
                    phone_number TEXT NOT NULL,
                    mcc_mnc TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    cef_message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            await self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts (id DESC)"
            )
            await self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts (severity)"
            )
            await self._conn.commit()
        logger.info("SQLite alert audit database initialized at '%s'.", self.db_path)

    async def close(self) -> None:
        """Closes the SQLite database connection."""
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None

    async def check_ready(self) -> tuple[bool, int, Optional[str]]:
        """Pings SQLite audit DB and returns total stored alerts."""
        async with self._lock:
            if self._conn is None:
                return False, 0, "Audit SQLite connection is not initialized"
            try:
                async with self._conn.execute("SELECT COUNT(*) FROM security_alerts") as cursor:
                    row = await cursor.fetchone()
                    count = int(row[0]) if row else 0
                return True, count, None
            except Exception as exc:
                return False, 0, str(exc)

    async def save_alert(
        self,
        event: IncomingInspectionEvent,
        severity: AlertSeverity,
        cef_message: str,
    ) -> SecurityAlertResponse:
        """Inserts a generated CEF security alert into the audit table."""
        alert_id = uuid4()
        created_at = datetime.now(timezone.utc)
        reasons_json = json.dumps(event.reasons, ensure_ascii=False)

        async with self._lock:
            if self._conn is None:
                raise RuntimeError("Audit SQLite database is not initialized")

            cursor = await self._conn.execute(
                """
                INSERT INTO security_alerts (
                    alert_id, request_id, severity, verdict, risk_score,
                    client_ip, phone_number, mcc_mnc, reasons_json,
                    cef_message, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(alert_id),
                    str(event.request_id),
                    severity.value,
                    event.verdict.upper(),
                    float(event.risk_score),
                    event.client_ip,
                    event.phone_number,
                    event.mcc_mnc,
                    reasons_json,
                    cef_message,
                    created_at.isoformat(),
                ),
            )
            await self._conn.commit()
            row_id = int(cursor.lastrowid or 0)

        return SecurityAlertResponse(
            id=row_id,
            alert_id=alert_id,
            request_id=event.request_id,
            severity=severity,
            verdict=event.verdict.upper(),
            risk_score=float(event.risk_score),
            client_ip=event.client_ip,
            phone_number=event.phone_number,
            mcc_mnc=event.mcc_mnc,
            reasons=list(event.reasons),
            cef_message=cef_message,
            created_at=created_at,
        )

    async def get_recent_alerts(
        self,
        limit: int = settings.DEFAULT_ALERTS_LIMIT,
        severity: Optional[AlertSeverity] = None,
    ) -> list[SecurityAlertResponse]:
        """Returns the most recent security alerts ordered newest first."""
        async with self._lock:
            if self._conn is None:
                raise RuntimeError("Audit SQLite database is not initialized")

            if severity is not None:
                query = (
                    "SELECT id, alert_id, request_id, severity, verdict, risk_score, "
                    "client_ip, phone_number, mcc_mnc, reasons_json, cef_message, created_at "
                    "FROM security_alerts WHERE severity = ? ORDER BY id DESC LIMIT ?"
                )
                params: tuple[object, ...] = (severity.value, limit)
            else:
                query = (
                    "SELECT id, alert_id, request_id, severity, verdict, risk_score, "
                    "client_ip, phone_number, mcc_mnc, reasons_json, cef_message, created_at "
                    "FROM security_alerts ORDER BY id DESC LIMIT ?"
                )
                params = (limit,)

            async with self._conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()

        alerts: list[SecurityAlertResponse] = []
        for row in rows:
            alerts.append(
                SecurityAlertResponse(
                    id=int(row["id"]),
                    alert_id=UUID(row["alert_id"]),
                    request_id=UUID(row["request_id"]),
                    severity=AlertSeverity(row["severity"]),
                    verdict=row["verdict"],
                    risk_score=float(row["risk_score"]),
                    client_ip=row["client_ip"],
                    phone_number=row["phone_number"],
                    mcc_mnc=row["mcc_mnc"],
                    reasons=json.loads(row["reasons_json"]),
                    cef_message=row["cef_message"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
            )
        return alerts
