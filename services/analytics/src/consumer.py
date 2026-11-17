"""
RabbitMQ consumer with buffered batch ingestion into ClickHouse.
Subscribes to queue 'analytics.raw_events' bound to exchange 'antifraud.events'
with routing key 'inspection.completed'. Flushes every 50 items or every 2 seconds.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)
from pydantic import ValidationError

from .config import settings
from .schemas import IncomingInspectionEvent
from .storage import ClickHouseStorage

logger = logging.getLogger(settings.SERVICE_NAME)


class AnalyticsConsumer:
    """
    Consumes inspection events from RabbitMQ and performs batched ClickHouse inserts
    triggered either when buffer size reaches `batch_size` (50) or every `flush_interval` (2s).
    """

    def __init__(
        self,
        storage: ClickHouseStorage,
        rabbitmq_url: str = settings.RABBITMQ_URL,
        exchange_name: str = settings.RABBITMQ_EXCHANGE,
        queue_name: str = settings.RABBITMQ_QUEUE,
        routing_key: str = settings.RABBITMQ_ROUTING_KEY,
        batch_size: int = settings.BATCH_SIZE,
        flush_interval: float = settings.FLUSH_INTERVAL_SECONDS,
        prefetch_count: int = settings.RABBITMQ_PREFETCH_COUNT,
    ) -> None:
        self.storage = storage
        self.rabbitmq_url = rabbitmq_url
        self.exchange_name = exchange_name
        self.queue_name = queue_name
        self.routing_key = routing_key
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.prefetch_count = prefetch_count

        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._queue: Optional[AbstractQueue] = None
        self._consumer_tag: Optional[str] = None

        self._buffer: list[tuple[list[object], AbstractIncomingMessage]] = []
        self._buffer_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task[None]] = None
        self._running: bool = False

    @property
    def buffered_count(self) -> int:
        return len(self._buffer)

    @property
    def is_connected(self) -> bool:
        return (
            self._connection is not None
            and not self._connection.is_closed
            and self._channel is not None
            and not self._channel.is_closed
        )

    async def start(self) -> None:
        """Connects to RabbitMQ, binds 'analytics.raw_events', and starts flush loop."""
        self._running = True
        self._flush_task = asyncio.create_task(self._periodic_flush_loop())

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

        self._consumer_tag = await self._queue.consume(
            self.handle_message,
            no_ack=False,
        )
        logger.info(
            "Analytics consumer listening on queue '%s' (exchange='%s', routing_key='%s', "
            "batch_size=%d, flush_interval=%.1fs)",
            self.queue_name,
            self.exchange_name,
            self.routing_key,
            self.batch_size,
            self.flush_interval,
        )

    async def stop(self) -> None:
        """Cancels consumer, flushes any remaining buffered events, and closes AMQP."""
        self._running = False

        if self._queue is not None and self._consumer_tag is not None:
            try:
                await self._queue.cancel(self._consumer_tag)
            except Exception as exc:
                logger.warning("Failed to cancel RabbitMQ consumer cleanly: %s", exc)
            self._consumer_tag = None

        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

        # Drain remaining buffered messages before closing channel
        await self.flush()

        if self._channel is not None and not self._channel.is_closed:
            await self._channel.close()
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()

        self._queue = None
        self._channel = None
        self._connection = None

    async def handle_message(self, message: AbstractIncomingMessage) -> None:
        """
        Parses an incoming RabbitMQ event and appends it to the in-memory batch buffer.
        Rejects malformed payloads without requeuing; triggers immediate flush at `batch_size`.
        """
        try:
            payload = json.loads(message.body.decode("utf-8"))
            event = IncomingInspectionEvent.model_validate(payload)
            row = event.to_clickhouse_row()
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            logger.warning(
                "Dropping malformed analytics message (delivery_tag=%s): %s",
                getattr(message, "delivery_tag", None),
                exc,
            )
            await message.reject(requeue=False)
            return

        should_flush = False
        async with self._buffer_lock:
            self._buffer.append((row, message))
            if len(self._buffer) >= self.batch_size:
                should_flush = True

        if should_flush:
            await self.flush()

    async def flush(self) -> int:
        """
        Atomically swaps the current buffer and executes a batch INSERT into ClickHouse.
        Acknowledges all messages on success; nacks with requeue on failure.
        Returns the number of inserted rows.
        """
        async with self._buffer_lock:
            if not self._buffer:
                return 0
            batch = self._buffer
            self._buffer = []

        rows = [row for row, _ in batch]
        messages = [msg for _, msg in batch]

        try:
            inserted = await self.storage.insert_batch(rows)
            for msg in messages:
                await msg.ack()
            logger.info("Flushed batch of %d events into ClickHouse sms_inspections.", inserted)
            return inserted
        except Exception as exc:
            logger.error(
                "Batch insert into ClickHouse failed (%s: %s); nacking %d messages for requeue",
                type(exc).__name__,
                exc,
                len(messages),
            )
            for msg in messages:
                try:
                    await msg.nack(requeue=True)
                except Exception as nack_exc:
                    logger.warning("Failed to nack message: %s", nack_exc)
            return 0

    async def _periodic_flush_loop(self) -> None:
        """Background timer flushing buffered events every `flush_interval` seconds."""
        while self._running:
            await asyncio.sleep(self.flush_interval)
            if self._buffer:
                await self.flush()
