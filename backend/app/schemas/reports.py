"""Pydantic schemas for scan history and reports endpoints."""
from __future__ import annotations

import json
from datetime import datetime

from pydantic import AliasChoices, BaseModel, Field


class IndicatorItem(BaseModel):
    id: str | None = None
    name: str
    detail: str
    severity: str
    weight: int | None = None


class ScanListItem(BaseModel):
    id: int
    scan_type: str
    target: str
    risk_level: str
    risk_score: int
    scanned_at: datetime = Field(validation_alias=AliasChoices("scanned_at", "created_at"))

    model_config = {"from_attributes": True, "populate_by_name": True}


class ScanDetail(BaseModel):
    id: int
    scan_type: str
    target: str
    risk_level: str
    risk_score: int
    summary: str | None = None
    indicators: list[IndicatorItem] = []
    recommendations: list[str] = []
    scanned_at: datetime = Field(validation_alias=AliasChoices("scanned_at", "created_at"))

    model_config = {"from_attributes": True, "populate_by_name": True}

    @classmethod
    def from_orm_with_json(cls, scan) -> "ScanDetail":
        """Build ScanDetail from a Scan ORM object, parsing JSON columns."""
        indicators = []
        if scan.indicators:
            try:
                raw = json.loads(scan.indicators)
                indicators = [IndicatorItem(**i) for i in raw]
            except Exception:
                pass

        recommendations = []
        if scan.recommendations:
            try:
                recommendations = json.loads(scan.recommendations)
            except Exception:
                pass

        return cls(
            id=scan.id,
            scan_type=scan.scan_type.value if hasattr(scan.scan_type, "value") else scan.scan_type,
            target=scan.target,
            risk_level=scan.risk_level.value if hasattr(scan.risk_level, "value") else scan.risk_level,
            risk_score=scan.risk_score,
            summary=scan.summary,
            indicators=indicators,
            recommendations=recommendations,
            scanned_at=scan.created_at,
        )


class ScanListResponse(BaseModel):
    items: list[ScanListItem]
    total: int
    page: int
    per_page: int
    pages: int


class ReportSummary(BaseModel):
    """Aggregate report derived from scan data — no separate DB table."""
    total_scans: int
    by_type: dict[str, int]
    by_risk: dict[str, int]
    score: int | None
    generated_at: datetime
