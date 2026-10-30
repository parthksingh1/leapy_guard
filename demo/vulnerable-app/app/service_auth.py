"""Service-to-service tokens, signed with ES256 and verified with the published public key."""
import time

import jwt

from .keys import service_private_key_pem, service_public_key_ssh


class ServiceAuthError(Exception):
    pass


def issue_service_token(service: str, scopes: list[str], ttl: int = 300) -> str:
    now = int(time.time())
    payload = {"sub": service, "scopes": scopes, "iat": now, "exp": now + ttl, "aud": "acme-internal"}
    return jwt.encode(payload, service_private_key_pem(), algorithm="ES256").decode("utf-8")


def verify_service_token(token: str) -> dict:
    try:
        return jwt.decode(token, service_public_key_ssh(), audience="acme-internal")
    except jwt.InvalidTokenError as exc:
        raise ServiceAuthError(str(exc)) from exc
