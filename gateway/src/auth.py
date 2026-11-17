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

from fastapi import HTTPException, Request, status

from .config import settings


def _matches_any_api_key(candidate: str) -> bool:
    if not candidate:
        return False
    return any(hmac.compare_digest(candidate, valid) for valid in settings.valid_api_keys)


def _matches_basic_auth(encoded_token: str) -> bool:
    try:
        decoded = base64.b64decode(encoded_token, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False

    if ":" not in decoded:
        return False

    username, password = decoded.split(":", 1)
    user_ok = hmac.compare_digest(username, settings.BASIC_AUTH_USERNAME)
    pass_ok = hmac.compare_digest(password, settings.BASIC_AUTH_PASSWORD)
    return user_ok and pass_ok


async def verify_client_auth(request: Request) -> str:
    """
    FastAPI dependency enforcing Bearer API Key, X-API-Key, or Basic Auth.
    Returns an authenticated principal identifier or raises HTTP 401.
    """
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header and _matches_any_api_key(api_key_header.strip()):
        return "api-key-client"

    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.strip().split(" ", 1)
        if len(parts) == 2:
            scheme, credential = parts[0].lower(), parts[1].strip()
            if scheme == "bearer" and _matches_any_api_key(credential):
                return "bearer-client"
            if scheme == "basic" and _matches_basic_auth(credential):
                return f"basic:{settings.BASIC_AUTH_USERNAME}"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials (Bearer API Key, X-API-Key, or Basic Auth required)",
        headers={"WWW-Authenticate": 'Bearer realm="antifraud-gateway", Basic realm="antifraud-gateway"'},
    )
