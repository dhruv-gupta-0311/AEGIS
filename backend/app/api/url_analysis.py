"""URL analysis API route — POST /api/v1/analysis/url"""

import json
import time
from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.database import get_db
from backend.app.models.scan import RiskLevel, Scan, ScanType
from backend.app.models.user import User
from backend.app.schemas.url_analysis import UrlAnalysisRequest, UrlAnalysisResult
from backend.app.services.url_analyzer import (
    ANALYSIS_VERSION,
    analyse_url,
    redact_url_for_storage,
)

router = APIRouter(prefix="/v1/analysis", tags=["analysis"])

_RATE_LIMIT = 30
_RATE_WINDOW = 60

_rate_store: dict[int, list[float]] = defaultdict(list)
_rate_lock = Lock()


def _check_rate_limit(user_id: int) -> None:
    now = time.monotonic()
    with _rate_lock:
        window_start = now - _RATE_WINDOW
        timestamps = [t for t in _rate_store[user_id] if t > window_start]
        if len(timestamps) >= _RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {_RATE_LIMIT} URL scans per minute.",
            )
        timestamps.append(now)
        _rate_store[user_id] = timestamps


@router.post(
    "/url",
    response_model=UrlAnalysisResult,
    status_code=status.HTTP_200_OK,
    summary="Analyse a URL for phishing and threat indicators",
)
def analyse_url_endpoint(
    payload: UrlAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UrlAnalysisResult:
    _check_rate_limit(current_user.id)

    try:
        normalized, score, level, indicators, recommendations = analyse_url(payload.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    safe_target = redact_url_for_storage(payload.url)[:2048]

    # Legacy summary: list of indicator ids (kept for backwards compat)
    summary_items = [i.id or i.name for i in indicators]
    summary = json.dumps(summary_items)
    while len(summary) > 500 and summary_items:
        summary_items.pop()
        summary = json.dumps(summary_items)

    # Full indicator objects stored as JSON
    indicators_json = json.dumps([
        {"id": i.id, "name": i.name, "detail": i.detail, "severity": i.severity, "weight": i.weight}
        for i in indicators
    ])
    recommendations_json = json.dumps(recommendations)

    scan = Scan(
        user_id=current_user.id,
        scan_type=ScanType.url,
        target=safe_target,
        risk_level=RiskLevel(level),
        risk_score=score,
        summary=summary,
        indicators=indicators_json,
        recommendations=recommendations_json,
    )
    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to save scan result.")

    return UrlAnalysisResult(
        scan_id=scan.id,
        normalized_url=normalized,
        risk_score=score,
        risk_level=level,
        indicators=indicators,
        recommendations=recommendations,
        scanned_at=scan.created_at,
        analysis_version=ANALYSIS_VERSION,
    )
