from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

from app.models.entities import AssetType


class ScannerKind(str, Enum):
    DNS = "dns"
    PORT = "port"
    SSL = "ssl"
    CLOUD = "cloud"
    VULNERABILITY = "vulnerability"


@dataclass
class DiscoveredAsset:
    asset_type: AssetType
    identifier: str
    display_name: str | None = None
    payload: dict = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class ScanContext:
    organization_id: str
    root_domains: list[str]
    cloud_accounts: dict | None = None


class BaseScanner(ABC):
    kind: ScannerKind

    @abstractmethod
    async def scan(self, context: ScanContext) -> list[DiscoveredAsset]:
        raise NotImplementedError
