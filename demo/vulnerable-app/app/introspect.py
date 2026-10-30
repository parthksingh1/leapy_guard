"""Helpers for logging and debugging tokens without trusting them."""
import jwt


def peek_claims(token: str) -> dict:
    """Read claims without verifying the signature (for logs only, never for auth)."""
    return jwt.decode(token, verify=False)


def token_subject(token: str) -> str | None:
    try:
        return peek_claims(token).get("sub")
    except jwt.DecodeError:
        return None
