"""Scan database model — stores metadata for every analysis, never raw passwords."""

import enum
import json
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class ScanType(str, enum.Enum):
    url      = "url"
    phishing = "phishing"
    password = "password"


class RiskLevel(str, enum.Enum):
    safe     = "safe"
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int]         = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int]    = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    scan_type: Mapped[ScanType]   = mapped_column(Enum(ScanType), nullable=False)
    target: Mapped[str]     = mapped_column(String(2048), nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    summary: Mapped[str]    = mapped_column(Text, nullable=True)       # legacy: JSON list of indicator IDs
    indicators: Mapped[str] = mapped_column(Text, nullable=True)       # JSON list of full indicator objects
    recommendations: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list of recommendation strings
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ---------------------------------------------------------------------------
    # Helpers — parse JSON columns safely
    # ---------------------------------------------------------------------------
    def get_indicators(self) -> list:
        if not self.indicators:
            return []
        try:
            return json.loads(self.indicators)
        except Exception:
            return []

    def get_recommendations(self) -> list:
        if not self.recommendations:
            return []
        try:
            return json.loads(self.recommendations)
        except Exception:
            return []
