from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.entities import AssetType, ChangeType, RiskLevel, ScanStatus, UserRole


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    email: str
    role: UserRole
    is_active: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class DomainVerificationResponse(BaseModel):
    domain: str
    verified: bool
    verified_at: datetime | None = None
    txt_record_name: str
    txt_record_value: str


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9-]+$")
    root_domains: list[str] = Field(min_length=1)
    cloud_accounts: dict | None = None


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    root_domains: list
    cloud_accounts: dict | None
    is_active: bool
    created_at: datetime


class ScanRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    asset_count: int
    error_message: str | None


class ChangeEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    change_type: ChangeType
    asset_type: AssetType
    identifier: str
    risk_level: RiskLevel
    risk_score: float
    summary: str
    previous_value: dict | None
    current_value: dict | None
    detected_at: datetime


class RiskAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    total_assets: int
    previous_total_assets: int | None
    risk_score: float
    previous_risk_score: float | None
    risk_delta_percent: float | None
    breakdown: dict
    assessed_at: datetime


class AIInsightResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    summary: str
    risk_commentary: str
    recommendations: list
    attack_scenarios: list = []
    action_items: list = []
    ollama_connected: bool = False
    model_name: str
    generated_at: datetime


class SystemStatusResponse(BaseModel):
    ollama: dict
    ai_enabled: bool


class ScannerModuleStatus(BaseModel):
    module: str
    label: str
    status: str
    asset_count: int = 0
    mode: str
    note: str = ""
    error: str | None = None


class SystemInfoResponse(BaseModel):
    app_name: str
    version: str
    deployment_mode: str
    demo_mode_enabled: bool
    capabilities: dict
    scanner_modes: dict
    roadmap: list[str]
    demo_notice: str | None = None


class AssetInventoryItem(BaseModel):
    asset_type: str
    label: str
    count: int
    description: str


class PerimeterInfo(BaseModel):
    root_domains: list[str]
    cloud_providers: list[str]
    monitored_surface: list[str]


class DashboardSummary(BaseModel):
    organization_id: UUID
    organization_name: str
    latest_scan: ScanRunResponse | None
    total_assets: int
    previous_total_assets: int | None
    risk_score: float
    previous_risk_score: float | None
    risk_delta_percent: float | None
    recent_changes: list[ChangeEventResponse]
    ai_insight: AIInsightResponse | None
    asset_inventory: list[AssetInventoryItem] = []
    risk_breakdown: dict | None = None
    critical_findings: list[str] = []
    perimeter: PerimeterInfo | None = None
    scan_coverage: list[str] = []
    executive_summary: str | None = None
    ollama_status: dict | None = None
    deployment_mode: str = "production"
    is_demo_organization: bool = False
    scanner_modules: list[ScannerModuleStatus] = []
    demo_notice: str | None = None


class TimelinePoint(BaseModel):
    date: datetime
    asset_count: int
    risk_score: float


class TimelineResponse(BaseModel):
    organization_id: UUID
    points: list[TimelinePoint]
