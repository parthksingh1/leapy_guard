import os
from dataclasses import dataclass, field


@dataclass
class Config:
    secret_key: str = field(default_factory=lambda: os.environ.get("AUTH_SECRET", "dev-secret-change-me"))
    issuer: str = "acme-auth"
    access_ttl_seconds: int = 900
    refresh_ttl_seconds: int = 60 * 60 * 24 * 7
    algorithm: str = "HS256"
