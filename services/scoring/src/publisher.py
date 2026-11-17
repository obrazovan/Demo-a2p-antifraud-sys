"""
Async RabbitMQ event publisher using aio_pika.
Publishes InspectionCompletedEvent messages to topic exchange 'antifraud.events'
with routing key 'inspection.completed'.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractExchange, AbstractRobustConnection

from .config import settings
from .schemas import InspectionCompletedEvent

logger = logging.getLogger(settings.SERVICE_NAME)


class RabbitMQPublisher:
    """Manages a robust aio_pika connection and publishes scoring events."""

    def __init__(
        self,
        rabbitmq_url: str = settings.RABBITMQ_URL,
        exchange_name: str = settings.RABBITMQ_EXCHANGE,
        routing_key: str = settings.RABBITMQ_ROUTING_KEY,
    ) -> None:
        self.rabbitmq_url = rabbitmq_url
        self.exchange_name = exchange_name
        self.routing_key = routing_key

        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._exchange: Optional[AbstractExchange] = None

    async def connect(self) -> None:
        """Establishes a robust AMQP connection and declares the durable topic exchange."""
        self._connection = await aio_pika.connect_robust(
            self.rabbitmq_url,
            timeout=settings.RABBITMQ_CONNECT_TIMEOUT,
        )
        self._channel = await self._connection.channel()
        self._exchange = await self._channel.declare_exchange(
            self.exchange_name,
            aio_pika.ExchangeType.TOPIC,
            durable=True,
        )
        logger.info(
            "Connected to RabbitMQ and declared durable topic exchange '%s'",
            self.exchange_name,
        )

    async def close(self) -> None:
        """Closes the AMQP channel and connection gracefully."""
        if self._channel is not None and not self._channel.is_closed:
            await self._channel.close()
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()
        self._exchange = None
        self._channel = None
        self._connection = None

    def check_ready(self) -> tuple[bool, Optional[str]]:
        """Verifies that RabbitMQ connection, channel, and exchange are active."""
        if self._connection is None or self._connection.is_closed:
            return False, "RabbitMQ connection is not established or closed"
        if self._channel is None or self._channel.is_closed:
            return False, "RabbitMQ channel is not open"
        if self._exchange is None:
            return False, f"RabbitMQ exchange '{self.exchange_name}' is not declared"
        return True, None

    async def publish_inspection_completed(
        self,
        event: InspectionCompletedEvent,
    ) -> bool:
        """
        Publishes the completed inspection event to exchange 'antifraud.events'
        under routing key 'inspection.completed'.
        Returns True on success, False if broker is unavailable (without failing the verdict).
        """
        is_ok, reason = self.check_ready()
        if not is_ok or self._exchange is None:
            logger.warning(
                "RabbitMQ publisher unavailable (%s); skipping event %s",
                reason,
                event.event_id,
            )
            return False

        message = aio_pika.Message(
            body=event.model_dump_json().encode("utf-8"),
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            message_id=str(event.event_id),
            correlation_id=str(event.request_id),
            headers={"X-Request-ID": str(event.request_id)},
        )

        try:
            await asyncio.wait_for(
                self._exchange.publish(message, routing_key=self.routing_key),
                timeout=settings.RABBITMQ_PUBLISH_TIMEOUT,
            )
            logger.info(
                "Published event %s to exchange '%s' with routing_key '%s'",
                event.event_id,
                self.exchange_name,
                self.routing_key,
            )
            return True
        except Exception as exc:
            logger.warning(
                "Failed to publish inspection event %s (%s: %s)",
                event.event_id,
                type(exc).__name__,
                exc,
            )
            return False
