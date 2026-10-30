"""Service signing keys (ES256). Generated per process for the demo; real deployments load from a KMS."""
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


@lru_cache(maxsize=1)
def _private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def service_private_key_pem() -> bytes:
    return _private_key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def service_public_key_ssh() -> bytes:
    """Public key in OpenSSH format, as published to partner services."""
    return _private_key().public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    )
