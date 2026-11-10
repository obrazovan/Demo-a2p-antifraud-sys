"""
Structured JSON logger module for the Anti-Fraud Microservice Platform.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator, Optional

from shared.schemas import CommonJSONFormatter, request_id_ctx, setup_structured_logging


def get_logger(service_name: str, level: str = "INFO") -> logging.Logger:
    """Convenience getter for configured structured JSON logger."""
    return setup_structured_logging(service_name=service_name, level=level)


def set_request_id(request_id: Optional[str]) -> None:
    """Sets the active request_id in context storage."""
    request_id_ctx.set(request_id)


def get_request_id() -> Optional[str]:
    """Retrieves the active request_id from context storage."""
    return request_id_ctx.get()


@contextmanager
def request_context(request_id: str) -> Generator[None, None, None]:
    """Context manager setting and resetting request correlation ID."""
    token = request_id_ctx.set(request_id)
    try:
        yield
    finally:
        request_id_ctx.reset(token)


__all__ = [
    "CommonJSONFormatter",
    "request_id_ctx",
    "setup_structured_logging",
    "get_logger",
    "set_request_id",
    "get_request_id",
    "request_context",
]

