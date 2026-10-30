from flask import Blueprint, current_app, jsonify, request

from .introspect import token_subject
from .service_auth import ServiceAuthError, verify_service_token
from .tokens import (
    TokenError,
    issue_access_token,
    issue_refresh_token,
    verify_access_token,
    verify_refresh_token,
)

bp = Blueprint("auth", __name__)

USERS = {
    "alice": {"password": "wonderland", "roles": ["admin"]},
    "bob": {"password": "builder", "roles": ["user"]},
}


def _cfg():
    return current_app.config["AUTH"]


def _bearer() -> str:
    header = request.headers.get("Authorization", "")
    return header[7:] if header.startswith("Bearer ") else ""


@bp.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    user = USERS.get(body.get("username", ""))
    if not user or user["password"] != body.get("password"):
        return jsonify(error="invalid credentials"), 401
    return jsonify(
        access_token=issue_access_token(_cfg(), body["username"], user["roles"]),
        refresh_token=issue_refresh_token(_cfg(), body["username"]),
    )


@bp.get("/me")
def me():
    try:
        claims = verify_access_token(_cfg(), _bearer())
    except TokenError as exc:
        current_app.logger.info("rejected token for %s", token_subject(_bearer()))
        return jsonify(error=str(exc)), 401
    return jsonify(user=claims["sub"], roles=claims["roles"])


@bp.post("/refresh")
def refresh():
    body = request.get_json(silent=True) or {}
    try:
        claims = verify_refresh_token(_cfg(), body.get("refresh_token", ""))
    except TokenError as exc:
        return jsonify(error=str(exc)), 401
    roles = USERS.get(claims["sub"], {}).get("roles", [])
    return jsonify(access_token=issue_access_token(_cfg(), claims["sub"], roles))


@bp.post("/internal/sync")
def internal_sync():
    try:
        claims = verify_service_token(_bearer())
    except ServiceAuthError as exc:
        return jsonify(error=str(exc)), 401
    if "sync:write" not in claims.get("scopes", []):
        return jsonify(error="missing scope"), 403
    return jsonify(ok=True, service=claims["sub"])
