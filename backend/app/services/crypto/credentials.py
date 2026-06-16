import base64
import json

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


def _fernet() -> Fernet:
    settings = get_settings()
    raw = settings.secret_key.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)


def encrypt_cloud_accounts(data: dict | None) -> str | None:
    if not data:
        return None
    token = _fernet().encrypt(json.dumps(data).encode("utf-8"))
    return token.decode("utf-8")


def decrypt_cloud_accounts(cipher: str | None) -> dict | None:
    if not cipher:
        return None
    try:
        raw = _fernet().decrypt(cipher.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except (InvalidToken, json.JSONDecodeError):
        return None
