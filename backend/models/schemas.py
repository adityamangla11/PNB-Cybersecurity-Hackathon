from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ScanRequest(BaseModel):
    targets: list[str]  # list of host or host:port


class ScanResponse(BaseModel):
    id: int
    status: str
    total_targets: int
    completed_targets: int
    created_at: datetime

    class Config:
        from_attributes = True


class AssetSummary(BaseModel):
    id: int
    host: str
    port: int
    asset_type: str
    highest_tls_version: Optional[str] = None
    cert_key_type: Optional[str] = None
    cert_key_size: Optional[int] = None
    cert_signature_algorithm: Optional[str] = None
    cert_not_after: Optional[datetime] = None
    score: float
    label: str
    scanned_at: datetime

    class Config:
        from_attributes = True


class AssetDetail(AssetSummary):
    scan_id: int
    tls_versions: Optional[list[str]] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[datetime] = None
    cert_serial_number: Optional[str] = None
    cipher_suites: Optional[list[dict]] = None
    key_exchange_algorithms: Optional[list[str]] = None
    classification_details: Optional[dict] = None
    recommendations: Optional[list[dict]] = None


class DashboardSummary(BaseModel):
    total_assets: int
    pqc_ready: int
    quantum_safe: int
    at_risk: int
    critical: int
    label_distribution: dict[str, int]
    score_trend: list[dict]  # [{scan_id, date, avg_score}]
    recent_scans: list[ScanResponse]
