from app.models.entities import Organization
from app.services.crypto.credentials import decrypt_cloud_accounts, encrypt_cloud_accounts


def get_cloud_accounts(org: Organization) -> dict | None:
    if org.cloud_accounts_encrypted:
        return decrypt_cloud_accounts(org.cloud_accounts_encrypted)
    return org.cloud_accounts


def set_cloud_accounts(org: Organization, data: dict | None) -> None:
    if data:
        org.cloud_accounts_encrypted = encrypt_cloud_accounts(data)
        org.cloud_accounts = None
    else:
        org.cloud_accounts_encrypted = None
        org.cloud_accounts = None
