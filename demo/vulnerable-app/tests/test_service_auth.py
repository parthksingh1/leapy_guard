import pytest

from app.service_auth import ServiceAuthError, issue_service_token, verify_service_token


def test_service_token_roundtrip():
    token = issue_service_token("billing", ["sync:write"])
    claims = verify_service_token(token)
    assert claims["sub"] == "billing"


def test_service_token_tampered_rejected():
    token = issue_service_token("billing", ["sync:write"])
    head, body, sig = token.split(".")
    with pytest.raises(ServiceAuthError):
        verify_service_token(f"{head}.{body}.{sig[:-4]}AAAA")
