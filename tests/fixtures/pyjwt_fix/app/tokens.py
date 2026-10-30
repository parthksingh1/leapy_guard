"""User access and refresh tokens."""
import time
import uuid

import jwt

from .config import Config


class TokenError(Exception):
    pass


def issue_access_token(cfg: Config, user_id: str, roles: list[str]) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "roles": roles,
        "iss": cfg.issuer,
        "iat": now,
        "exp": now + cfg.access_ttl_seconds,
        "type": "access",
    }
    return jwt.encode(payload, cfg.secret_key, algorithm=cfg.algorithm)


def issue_refresh_token(cfg: Config, user_id: str) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "jti": uuid.uuid4().hex,
        "iss": cfg.issuer,
        "iat": now,
        "exp": now + cfg.refresh_ttl_seconds,
        "type": "refresh",
    }
    token = jwt.encode(payload, cfg.secret_key, algorithm=cfg.algorithm)
    return token


def verify_access_token(cfg: Config, token: str) -> dict:
    try:
        claims = jwt.decode(token, cfg.secret_key, algorithms=[cfg.algorithm], issuer=cfg.issuer)
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}") from exc
    if claims.get("type") != "access":
        raise TokenError("not an access token")
    return claims


def verify_refresh_token(cfg: Config, token: str) -> dict:
    try:
        claims = jwt.decode(token, cfg.secret_key, algorithms=[cfg.algorithm], issuer=cfg.issuer)
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid refresh token: {exc}") from exc
    if claims.get("type") != "refresh":
        raise TokenError("not a refresh token")
    return claims
