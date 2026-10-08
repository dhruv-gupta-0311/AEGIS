import { useState, useEffect, useCallback } from 'react'
import { reports, scanHistory } from '../services/api'
import DashboardCard from '../components/DashboardCard'
import './ReportsPage.css'

const TYPE_LABEL = { url: 'URL', phishing: 'Email', password: 'Password' }
const RISK_ORDER = ['critical', 'high', 'medium', 'low', 'safe']
const RISK_COLORS = {
  critical: 'var(--danger)', high: '#f0803c',
  medium: 'var(--warning)', low: 'var(--info)', safe: 'var(--success)',
}
const RISK_TEXT = {
  safe: 'success', low: 'info', medium: 'warning', high: 'danger', critical: 'danger'
}

function scoreAccent(score) {
  if (score == null) return 'default'
  if (score >= 80) return 'success'
  if (score >= 60) return 'warning'
  return 'danger'
}

function topType(byType) {
  const entries = Object.entries(byType).filter(([, n]) => n > 0)
  if (!entries.length) return 'None'
  return TYPE_LABEL[entries.sort((a, b) => b[1] - a[1])[0][0]] ?? 'Mixed'
}

function BarRow({ label, count, total, color }) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0
  return (
    <div className="rp-bar-row">
      <span className="rp-bar-label">{label}</span>
      <div className="rp-bar-track">
        <div className="rp-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="rp-bar-count">{count}</span>
    </div>
  )
}

function downloadCSV(report) {
  const rows = [
    ['Category', 'Subcategory', 'Count'],
    ...Object.entries(report.by_type).map(([k, v]) => ['Type', TYPE_LABEL[k] ?? k, v]),
    ...RISK_ORDER.map(r => ['Risk', r.charAt(0).toUpperCase() + r.slice(1), report.by_risk[r] ?? 0]),
    ['Summary', 'Total scans', report.total_scans],
    ['Summary', 'Security score', report.score ?? 'N/A'],
  ]
  const csv  = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const a    = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob),
    download: `aegis-summary-${new Date().toISOString().slice(0, 10)}.csv`,
  })
  a.click()
  URL.revokeObjectURL(a.href)
}

function downloadHtmlReport(scanId) {
  const token = localStorage.getItem('aegis_token')
  const base  = import.meta.env.VITE_API_URL ?? '/api'
  fetch(`${base}/v1/reports/${scanId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  })
    .then(r => r.blob())
    .then(blob => {
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: `aegis-report-scan-${scanId}.html`,
      })
      a.click()
      URL.revokeObjectURL(a.href)
    })
    .catch(() => alert('Failed to download report.'))
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

export default function ReportsPage() {
  const [report,  setReport]  = useState(null)
  const [scans,   setScans]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  const load = useCallback(() => {
    setLoading(true); setError(null)
    Promise.all([
      reports.list(),
      scanHistory.list({ page: 1, per_page: 50 }),
    ])
      .then(([summary, history]) => {
        setReport(summary)
        setScans(history.items)
        setLoading(false)
      })
      .catch(err => { setError(err.message ?? 'Failed to load report.'); setLoading(false) })
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="rp-page">
      <div className="rp-header">
        <div>
          <h1 className="rp-title">Security Reports</h1>
          {!loading && report && (
            <p className="rp-subtitle">Generated {new Date(report.generated_at).toLocaleString()}</p>
          )}
        </div>
        <div className="rp-header-actions">
          <button className="rp-refresh-btn" onClick={load} disabled={loading}>Refresh</button>
          {report && report.total_scans > 0 && (
            <button className="rp-download-btn" onClick={() => downloadCSV(report)}>
              Download CSV
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="rp-error" role="alert">
          {error}<button className="rp-error-retry" onClick={load}>Retry</button>
        </div>
      )}

      {loading && (
        <div className="rp-skeleton-grid">
          {[1, 2, 3].map(i => <div key={i} className="rp-skeleton-card" />)}
        </div>
      )}

      {!loading && report && report.total_scans === 0 && (
        <div className="rp-empty">No scan data yet. Run some analyses to generate a report.</div>
      )}

      {!loading && report && report.total_scans > 0 && (
        <>
          {/* Metric cards */}
          <section className="rp-metrics">
            <DashboardCard
              title="Total Scans"
              value={report.total_scans}
              subtitle={`${topType(report.by_type)} most common`}
              accent="info"
            />
            <DashboardCard
              title="Security Score"
              value={report.score != null ? `${report.score}/100` : 'N/A'}
              subtitle={report.score == null ? 'No data' : report.score >= 80 ? 'Good' : report.score >= 60 ? 'Fair' : report.score >= 40 ? 'Poor' : 'Critical'}
              accent={scoreAccent(report.score)}
            />
            <DashboardCard
              title="High Risk Findings"
              value={(report.by_risk.critical ?? 0) + (report.by_risk.high ?? 0)}
              subtitle={`${report.by_risk.critical ?? 0} critical, ${report.by_risk.high ?? 0} high`}
              accent={(report.by_risk.critical ?? 0) + (report.by_risk.high ?? 0) > 0 ? 'danger' : 'success'}
            />
          </section>

          {/* Charts */}
          <section className="rp-charts">
            <DashboardCard title="By Scan Type">
              <div className="rp-bars">
                {Object.entries(report.by_type).map(([type, count]) => (
                  <BarRow key={type} label={TYPE_LABEL[type] ?? type} count={count} total={report.total_scans} color="var(--accent)" />
                ))}
              </div>
            </DashboardCard>
            <DashboardCard title="By Risk Level">
              <div className="rp-bars">
                {RISK_ORDER.map(risk => (
                  <BarRow key={risk} label={risk.charAt(0).toUpperCase() + risk.slice(1)} count={report.by_risk[risk] ?? 0} total={report.total_scans} color={RISK_COLORS[risk]} />
                ))}
              </div>
            </DashboardCard>
          </section>

          {/* Individual scan reports */}
          {scans.length > 0 && (
            <section className="rp-scan-list">
              <h2 className="rp-section-title">Individual Scan Reports</h2>
              <div className="rp-scan-table-wrap">
                <table className="rp-scan-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Target</th>
                      <th>Risk</th>
                      <th>Score</th>
                      <th>Date</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map(scan => {
                      const riskClass = RISK_TEXT[scan.risk_level] ?? 'default'
                      return (
                        <tr key={scan.id} className="rp-scan-row">
                          <td>
                            <span className={`rp-type-badge rp-type-badge--${scan.scan_type}`}>
                              {TYPE_LABEL[scan.scan_type] ?? scan.scan_type}
                            </span>
                          </td>
                          <td className="rp-target" title={scan.target}>
                            {scan.target.length > 50 ? scan.target.slice(0, 50) + '...' : scan.target}
                          </td>
                          <td>
                            <span className={`rp-risk rp-risk--${riskClass}`}>{scan.risk_level}</span>
                          </td>
                          <td className="rp-score">{scan.risk_score}</td>
                          <td className="rp-date">{formatDate(scan.scanned_at)}</td>
                          <td>
                            <button
                              className="rp-dl-btn"
                              onClick={() => downloadHtmlReport(scan.id)}
                              title="Download HTML report"
                            >
                              Download
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}
