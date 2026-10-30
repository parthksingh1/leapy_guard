import pytest

from app.config import Config
from app.introspect import peek_claims, token_subject
from app.tokens import (
    TokenError,
    issue_access_token,
    issue_refresh_token,
    verify_access_token,
    verify_refresh_token,
)


def test_access_token_is_str(cfg):
    token = issue_access_token(cfg, "alice", ["admin"])
    assert isinstance(token, str)
    assert token.count(".") == 2


def test_access_token_roundtrip(cfg):
    token = issue_access_token(cfg, "alice", ["admin"])
    claims = verify_access_token(cfg, token)
    assert claims["sub"] == "alice"
    assert claims["roles"] == ["admin"]


def test_refresh_token_roundtrip(cfg):
    token = issue_refresh_token(cfg, "bob")
    claims = verify_refresh_token(cfg, token)
    assert claims["sub"] == "bob"
    assert claims["type"] == "refresh"


def test_refresh_token_rejected_as_access(cfg):
    token = issue_refresh_token(cfg, "bob")
    with pytest.raises(TokenError):
        verify_access_token(cfg, token)


def test_wrong_secret_rejected(cfg):
    token = issue_access_token(cfg, "alice", ["admin"])
    with pytest.raises(TokenError):
        verify_access_token(Config(secret_key="other"), token)


def test_expired_token_rejected():
    cfg = Config(secret_key="test-secret", access_ttl_seconds=-10)
    token = issue_access_token(cfg, "alice", ["admin"])
    with pytest.raises(TokenError, match="expired"):
        verify_access_token(cfg, token)


def test_peek_claims_without_verification(cfg):
    token = issue_access_token(cfg, "alice", ["admin"])
    assert peek_claims(token)["sub"] == "alice"
    assert token_subject(token) == "alice"
    assert token_subject("not-a-token") is None
