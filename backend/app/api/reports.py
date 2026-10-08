"""Scan history and reports API."""
from __future__ import annotations

import math
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.database import get_db
from backend.app.models.scan import RiskLevel, Scan, ScanType
from backend.app.models.user import User
from backend.app.schemas.reports import (
    ReportSummary,
    ScanDetail,
    ScanListItem,
    ScanListResponse,
)

router = APIRouter(prefix="/v1", tags=["history"])

_MAX_PER_PAGE = 100


def _owned_scan_or_404(scan_id: int, user_id: int, db: Session) -> Scan:
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id, Scan.user_id == user_id)
        .first()
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.get("/scans", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=_MAX_PER_PAGE),
    scan_type: str | None = Query(None),
    risk_level: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanListResponse:
    q = db.query(Scan).filter(Scan.user_id == current_user.id)
    if scan_type:
        try:
            q = q.filter(Scan.scan_type == ScanType(scan_type))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid scan_type: {scan_type}")
    if risk_level:
        try:
            q = q.filter(Scan.risk_level == RiskLevel(risk_level))
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Invalid risk_level: {risk_level}")
    total: int = q.count()
    pages = max(1, math.ceil(total / per_page))
    items = q.order_by(Scan.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return ScanListResponse(
        items=[ScanListItem.model_validate(s) for s in items],
        total=total, page=page, per_page=per_page, pages=pages,
    )


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanDetail:
    scan = _owned_scan_or_404(scan_id, current_user.id, db)
    return ScanDetail.from_orm_with_json(scan)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    scan = _owned_scan_or_404(scan_id, current_user.id, db)
    db.delete(scan)
    db.commit()


@router.get("/reports", response_model=ReportSummary)
def get_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportSummary:
    uid = current_user.id
    risk_rows = (
        db.query(Scan.risk_level, func.count(Scan.id))
        .filter(Scan.user_id == uid).group_by(Scan.risk_level).all()
    )
    by_risk: dict[str, int] = {lvl.value: 0 for lvl in RiskLevel}
    for risk_level, count in risk_rows:
        by_risk[risk_level.value] = count
    total = sum(by_risk.values())
    type_rows = (
        db.query(Scan.scan_type, func.count(Scan.id))
        .filter(Scan.user_id == uid).group_by(Scan.scan_type).all()
    )
    by_type: dict[str, int] = {t.value: 0 for t in ScanType}
    for scan_type, count in type_rows:
        by_type[scan_type.value] = count
    score: int | None = None
    if total > 0:
        penalty = (
            by_risk.get("critical", 0) * 20 + by_risk.get("high", 0) * 12
            + by_risk.get("medium", 0) * 5 + by_risk.get("low", 0) * 1
        )
        score = max(0, 100 - penalty)
    return ReportSummary(
        total_scans=total, by_type=by_type, by_risk=by_risk,
        score=score, generated_at=datetime.now(timezone.utc),
    )


@router.get("/reports/{scan_id}", response_model=ScanDetail)
def get_report_detail(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanDetail:
    scan = _owned_scan_or_404(scan_id, current_user.id, db)
    return ScanDetail.from_orm_with_json(scan)


# ---------------------------------------------------------------------------
# HTML Report Download
# ---------------------------------------------------------------------------

_SEVERITY_COLOR = {
    "critical": "#f85149", "high": "#f0803c",
    "medium": "#d29922", "low": "#58a6ff", "info": "#8b949e",
}
_RISK_COLOR = {
    "critical": "#f85149", "high": "#f0803c",
    "medium": "#d29922", "low": "#58a6ff", "safe": "#3fb950",
}
_TYPE_LABEL = {"url": "URL Analysis", "phishing": "Email Analysis", "password": "Password Analysis"}


def _build_html_report(scan: Scan) -> str:
    detail = ScanDetail.from_orm_with_json(scan)
    risk_color = _RISK_COLOR.get(detail.risk_level, "#8b949e")
    scan_type_label = _TYPE_LABEL.get(detail.scan_type, detail.scan_type.title())
    scanned_at = detail.scanned_at.strftime("%d %B %Y at %H:%M UTC")

    indicators_html = ""
    if detail.indicators:
        rows = ""
        for ind in detail.indicators:
            sev_color = _SEVERITY_COLOR.get(ind.severity, "#8b949e")
            rows += f"""
            <tr>
                <td><span style="background:{sev_color}22;color:{sev_color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">{ind.severity}</span></td>
                <td style="font-weight:600">{ind.name}</td>
                <td style="color:#8b949e">{ind.detail}</td>
            </tr>"""
        indicators_html = f"""
        <div class="section">
            <h2>Indicators Detected ({len(detail.indicators)})</h2>
            <table>
                <thead><tr><th>Severity</th><th>Indicator</th><th>Detail</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""
    else:
        indicators_html = """<div class="section"><h2>Indicators Detected</h2><p class="muted">No indicators detected for this scan.</p></div>"""

    recs_html = ""
    if detail.recommendations:
        items = "".join(f"<li>{r}</li>" for r in detail.recommendations)
        recs_html = f"""<div class="section"><h2>Recommendations</h2><ul>{items}</ul></div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS Security Report — Scan #{detail.id}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #e6edf3; font-size: 14px; line-height: 1.6; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 40px 24px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 40px; padding-bottom: 24px; border-bottom: 1px solid #30363d; }}
  .brand {{ font-size: 22px; font-weight: 700; letter-spacing: 2px; color: #00d4aa; }}
  .meta {{ text-align: right; color: #8b949e; font-size: 12px; }}
  .meta p {{ margin-top: 4px; }}
  .score-block {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 28px; margin-bottom: 32px; display: flex; align-items: center; gap: 32px; }}
  .score-num {{ font-size: 48px; font-weight: 700; color: {risk_color}; line-height: 1; }}
  .score-label {{ font-size: 18px; font-weight: 600; color: {risk_color}; text-transform: capitalize; }}
  .score-sub {{ font-size: 13px; color: #8b949e; margin-top: 4px; }}
  .target-box {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin-bottom: 32px; }}
  .target-box .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; margin-bottom: 6px; }}
  .target-box code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; color: #e6edf3; word-break: break-all; }}
  .section {{ margin-bottom: 32px; }}
  .section h2 {{ font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
  th {{ background: #1c2333; padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; color: #8b949e; border-bottom: 1px solid #30363d; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #30363d; font-size: 13px; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  ul {{ padding-left: 20px; }}
  ul li {{ padding: 4px 0; font-size: 13px; color: #8b949e; }}
  .muted {{ color: #8b949e; font-style: italic; font-size: 13px; }}
  .footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid #30363d; font-size: 11px; color: #484f58; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">AEGIS</div>
    <div class="meta">
      <p><strong>{scan_type_label}</strong></p>
      <p>Scan #{detail.id}</p>
      <p>{scanned_at}</p>
    </div>
  </div>

  <div class="score-block">
    <div>
      <div class="score-num">{detail.risk_score}<span style="font-size:24px;color:#8b949e">/100</span></div>
    </div>
    <div>
      <div class="score-label">{detail.risk_level.capitalize()} Risk</div>
      <div class="score-sub">{len(detail.indicators)} indicator{"s" if len(detail.indicators) != 1 else ""} detected</div>
    </div>
  </div>

  <div class="target-box">
    <div class="label">Scanned Target</div>
    <code>{detail.target}</code>
  </div>

  {indicators_html}
  {recs_html}

  <div class="footer">
    <p>Generated by AEGIS &mdash; AI-powered personal cybersecurity dashboard.</p>
    <p>This report is based on deterministic heuristic analysis. Results are informational and should be verified independently before acting on them.</p>
  </div>
</div>
</body>
</html>"""


@router.get(
    "/reports/{scan_id}/download",
    response_class=HTMLResponse,
    summary="Download a self-contained HTML report for a single scan",
)
def download_scan_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    scan = _owned_scan_or_404(scan_id, current_user.id, db)
    html = _build_html_report(scan)
    filename = f"aegis-report-scan-{scan_id}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
