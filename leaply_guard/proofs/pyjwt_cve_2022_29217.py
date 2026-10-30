"""Security regression test for CVE-2022-29217 (PyJWT algorithm confusion).

An attacker who knows the service's *public* key signs a token with HS256, using the
public key bytes as the HMAC secret. A vulnerable verifier (PyJWT < 2.4.0, or any
jwt.decode call without an algorithms allow-list) accepts it. The fixed code must reject it.

The token is built by hand (no PyJWT) so the attack is identical before and after the upgrade.
"""
import base64
import hashlib
import hmac
import json
import time

import pytest

from app.keys import service_public_key_ssh
from app.service_auth import ServiceAuthError, verify_service_token


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_hs256(key: bytes, claims: dict) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


def test_cve_2022_29217_forged_hs256_token_is_rejected():
    now = int(time.time())
    forged = _forge_hs256(
        service_public_key_ssh(),
        {"sub": "attacker", "scopes": ["sync:write"], "iat": now, "exp": now + 300, "aud": "acme-internal"},
    )
    with pytest.raises(ServiceAuthError):
        verify_service_token(forged)
