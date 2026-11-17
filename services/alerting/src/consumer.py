"""
RabbitMQ security alert consumer using aio_pika.
Subscribes to queue 'security.alerts' bound to exchange 'antifraud.events'
with routing key 'inspection.completed' (and 'alert.#').
Generates CEF alerts for DENY or risk_score >= 80.0 events, emits structured
WARNING/ERROR JSON logs, and persists alerts to the SQLite audit trail.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)
from pydantic import ValidationError

from .cef import format_cef_alert, should_trigger_alert
from .config import settings
from .schemas import AlertSeverity, IncomingInspectionEvent
from .storage import AlertAuditStorage

logger = logging.getLogger(settings.SERVICE_NAME)


class AlertingConsumer:
    """Consumes inspection events and generates CEF security alerts on high-risk traffic."""

    def __init__(
        self,
        storage: AlertAuditStorage,
        rabbitmq_url: str = settings.RABBITMQ_URL,
        exchange_name: str = settings.RABBITMQ_EXCHANGE,
        queue_name: str = settings.RABBITMQ_QUEUE,
        routing_key: str = settings.RABBITMQ_ROUTING_KEY,
        alert_routing_key: str = settings.RABBITMQ_ALERT_ROUTING_KEY,
        critical_threshold: float = settings.CRITICAL_RISK_THRESHOLD,
        prefetch_count: int = settings.RABBITMQ_PREFETCH_COUNT,
    ) -> None:
        self.storage = storage
        self.rabbitmq_url = rabbitmq_url
        self.exchange_name = exchange_name
        self.queue_name = queue_name
        self.routing_key = routing_key
        self.alert_routing_key = alert_routing_key
        self.critical_threshold = critical_threshold
        self.prefetch_count = prefetch_count

        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._queue: Optional[AbstractQueue] = None
        self._consumer_tag: Optional[str] = None

    def check_ready(self) -> tuple[bool, Optional[str]]:
        """Verifies active RabbitMQ consumer connection and channel."""
        if self._connection is None or self._connection.is_closed:
            return False, "RabbitMQ consumer connection is not established or closed"
        if self._channel is None or self._channel.is_closed:
            return False, "RabbitMQ consumer channel is closed"
        return True, None

    async def start(self, max_retries: int = 10, retry_delay: float = 1.5) -> None:
        """Connects to RabbitMQ (with startup retries), binds 'security.alerts', and begins consuming."""
        last_exc: Optional[Exception] = None
        for attempt in range(1, max_retries + 1):
            try:
                self._connection = await aio_pika.connect_robust(
                    self.rabbitmq_url,
                    timeout=settings.RABBITMQ_CONNECT_TIMEOUT,
                )
                self._channel = await self._connection.channel()
                await self._channel.set_qos(prefetch_count=self.prefetch_count)

                exchange = await self._channel.declare_exchange(
                    self.exchange_name,
                    aio_pika.ExchangeType.TOPIC,
                    durable=True,
                )
                self._queue = await self._channel.declare_queue(
                    self.queue_name,
                    durable=True,
                )
                await self._queue.bind(exchange, routing_key=self.routing_key)
                await self._queue.bind(exchange, routing_key=self.alert_routing_key)

                self._consumer_tag = await self._queue.consume(
                    self.handle_message,
                    no_ack=False,
                )
                logger.info(
                    "Alerting consumer listening on queue '%s' (exchange='%s', keys=['%s', '%s'])",
                    self.queue_name,
                    self.exchange_name,
                    self.routing_key,
                    self.alert_routing_key,
                )
                return
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "Alerting RabbitMQ connect attempt %d/%d failed (%s: %s); retrying in %.1fs",
                    attempt,
                    max_retries,
                    type(exc).__name__,
                    exc,
                    retry_delay,
                )
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)

        if last_exc is not None:
            raise last_exc

    async def stop(self) -> None:
        """Stops consumer and closes AMQP channel and connection."""
        if self._queue is not None and self._consumer_tag is not None:
            try:
                await self._queue.cancel(self._consumer_tag)
            except Exception as exc:
                logger.warning("Failed to cancel Alerting consumer cleanly: %s", exc)
            self._consumer_tag = None

        if self._channel is not None and not self._channel.is_closed:
            await self._channel.close()
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()

        self._queue = None
        self._channel = None
        self._connection = None

    async def handle_message(self, message: AbstractIncomingMessage) -> None:
        """
        Evaluates incoming event. If verdict == DENY or risk_score >= 80.0:
          1. Formats CEF alert.
          2. Logs structured WARNING (HIGH) or ERROR (CRITICAL) with request_id.
          3. Persists to SQLite audit table.
          4. Acknowledges RabbitMQ message.
        """
        try:
            payload = json.loads(message.body.decode("utf-8"))
            event = IncomingInspectionEvent.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            logger.warning(
                "Dropping malformed alerting message (delivery_tag=%s): %s",
                getattr(message, "delivery_tag", None),
                exc,
            )
            await message.reject(requeue=False)
            return

        if not should_trigger_alert(event, critical_threshold=self.critical_threshold):
            await message.ack()
            return

        severity, cef_line = format_cef_alert(
            event,
            critical_threshold=self.critical_threshold,
        )

        try:
            saved = await self.storage.save_alert(
                event=event,
                severity=severity,
                cef_message=cef_line,
            )
        except Exception as exc:
            logger.error(
                "Failed to persist security alert for request %s (%s: %s); nacking for requeue",
                event.request_id,
                type(exc).__name__,
                exc,
                extra={"request_id": str(event.request_id)},
            )
            await message.nack(requeue=True)
            return

        if severity == AlertSeverity.CRITICAL:
            logger.error(
                cef_line,
                extra={"request_id": str(event.request_id)},
            )
        else:
            logger.warning(
                cef_line,
                extra={"request_id": str(event.request_id)},
            )

        await message.ack()
        logger.debug("Persisted security alert id=%d alert_id=%s", saved.id, saved.alert_id)
