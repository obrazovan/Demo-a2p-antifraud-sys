"""
Authentication dependency for API Gateway.
Supports:
  - Authorization: Bearer <api-key>
  - X-API-Key: <api-key>
  - Authorization: Basic <base64(username:password)>
Uses constant-time comparisons to prevent timing attacks.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)

from .config import settings

api_key_header_scheme = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="X-API-Key header authentication (value: antifraud-demo-key)",
)
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Bearer API key authentication (token: antifraud-demo-key)",
)
basic_scheme = HTTPBasic(
    auto_error=False,
    description="HTTP Basic authentication (admin / secret-admin-pass)",
)


def _matches_any_api_key(candidate: str) -> bool:
    if not candidate:
        return False
    return any(hmac.compare_digest(candidate, valid) for valid in settings.valid_api_keys)


def _matches_basic_auth(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username, settings.BASIC_AUTH_USERNAME)
    pass_ok = hmac.compare_digest(password, settings.BASIC_AUTH_PASSWORD)
    return user_ok and pass_ok


async def verify_client_auth(
    request: Request,
    api_key: Optional[str] = Depends(api_key_header_scheme),
    bearer_token: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    basic_creds: Optional[HTTPBasicCredentials] = Depends(basic_scheme),
) -> str:
    """
    FastAPI dependency enforcing Bearer API Key, X-API-Key, or Basic Auth.
    Returns an authenticated principal identifier or raises HTTP 401.
    """
    # 1. Check X-API-Key scheme
    if api_key and _matches_any_api_key(api_key.strip()):
        return "api-key-client"

    # Raw fallback
    raw_api_key = request.headers.get("X-API-Key")
    if raw_api_key and _matches_any_api_key(raw_api_key.strip()):
        return "api-key-client"

    # 2. Check Bearer token scheme
    if bearer_token and _matches_any_api_key(bearer_token.credentials.strip()):
        return "bearer-client"

    # 3. Check Basic auth scheme
    if basic_creds and _matches_basic_auth(basic_creds.username, basic_creds.password):
        return f"basic:{settings.BASIC_AUTH_USERNAME}"

    # 4. Fallback manual header parser
    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.strip().split(" ", 1)
        if len(parts) == 2:
            scheme, credential = parts[0].lower(), parts[1].strip()
            if scheme == "bearer" and _matches_any_api_key(credential):
                return "bearer-client"
            if scheme == "basic":
                try:
                    decoded = base64.b64decode(credential, validate=True).decode("utf-8")
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                        if _matches_basic_auth(u, p):
                            return f"basic:{settings.BASIC_AUTH_USERNAME}"
                except (binascii.Error, UnicodeDecodeError):
                    pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials (Bearer API Key, X-API-Key, or Basic Auth required)",
        headers={"WWW-Authenticate": 'Bearer realm="antifraud-gateway", Basic realm="antifraud-gateway"'},
    )
