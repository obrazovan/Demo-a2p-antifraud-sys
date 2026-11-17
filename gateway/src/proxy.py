"""
Async reverse proxy client for forwarding gateway requests to downstream microservices
with X-Request-ID propagation and standardized timeout/bad-gateway error handling.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx
from fastapi import HTTPException, Request, Response, status

from .config import settings

logger = logging.getLogger(settings.SERVICE_NAME)

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    }
)


class GatewayProxyClient:
    """Pooled async HTTP reverse proxy for internal microservice routing."""

    def __init__(
        self,
        scoring_url: str = settings.SCORING_URL,
        analytics_url: str = settings.ANALYTICS_URL,
        rule_engine_url: str = settings.RULE_ENGINE_URL,
        reputation_url: str = settings.REPUTATION_URL,
        alerting_url: str = settings.ALERTING_URL,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.scoring_url = scoring_url.rstrip("/")
        self.analytics_url = analytics_url.rstrip("/")
        self.rule_engine_url = rule_engine_url.rstrip("/")
        self.reputation_url = reputation_url.rstrip("/")
        self.alerting_url = alerting_url.rstrip("/")

        self._client: Optional[httpx.AsyncClient] = http_client
        self._owns_client: bool = http_client is None

    async def start(self) -> None:
        """Initializes pooled httpx.AsyncClient."""
        if self._client is None:
            timeout = httpx.Timeout(
                connect=settings.PROXY_CONNECT_TIMEOUT,
                read=settings.PROXY_READ_TIMEOUT,
                write=settings.PROXY_READ_TIMEOUT,
                pool=settings.PROXY_CONNECT_TIMEOUT,
            )
            limits = httpx.Limits(
                max_keepalive_connections=100,
                max_connections=200,
                keepalive_expiry=30.0,
            )
            self._client = httpx.AsyncClient(timeout=timeout, limits=limits)
            self._owns_client = True

    async def close(self) -> None:
        """Closes owned httpx.AsyncClient."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def forward(
        self,
        method: str,
        target_url: str,
        request_id: str,
        query_params: Optional[Any] = None,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
    ) -> Response:
        """Forwards an HTTP request downstream and mirrors status, body, and safe headers."""
        if self._client is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Gateway proxy client is not initialized",
            )

        headers: dict[str, str] = {"X-Request-ID": request_id}
        if content_type:
            headers["Content-Type"] = content_type

        try:
            upstream_resp = await self._client.request(
                method=method,
                url=target_url,
                params=query_params,
                content=body,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            logger.warning("Downstream request to %s timed out: %s", target_url, exc)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Downstream service timed out",
            )
        except httpx.HTTPError as exc:
            logger.warning("Downstream request to %s failed: %s", target_url, exc)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Downstream service is unreachable",
            )

        response_headers = {
            key: value
            for key, value in upstream_resp.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
        }
        response_headers["X-Request-ID"] = request_id

        return Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=response_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    async def proxy_fastapi_request(
        self,
        request: Request,
        target_url: str,
        request_id: str,
    ) -> Response:
        """Convenience helper reading incoming body/query params and forwarding downstream."""
        body = await request.body()
        return await self.forward(
            method=request.method,
            target_url=target_url,
            request_id=request_id,
            query_params=request.query_params,
            body=body if body else None,
            content_type=request.headers.get("content-type"),
        )

    async def check_downstreams_health(self) -> tuple[bool, dict[str, str]]:
        """Probes downstream microservices' /health endpoints in parallel."""
        if self._client is None:
            return False, {"scoring": "uninitialized"}

        targets = {
            "scoring": f"{self.scoring_url}/health",
            "rule_engine": f"{self.rule_engine_url}/health",
            "analytics": f"{self.analytics_url}/health",
            "alerting": f"{self.alerting_url}/health",
        }

        async def _probe(name: str, url: str) -> tuple[str, str]:
            try:
                resp = await asyncio.wait_for(
                    self._client.get(url),  # type: ignore[union-attr]
                    timeout=settings.READY_CHECK_TIMEOUT,
                )
                return name, "ok" if resp.status_code == 200 else f"http_{resp.status_code}"
            except Exception:
                return name, "unreachable"

        results = dict(await asyncio.gather(*(_probe(n, u) for n, u in targets.items())))
        is_ready = results.get("scoring") == "ok"
        return is_ready, results
