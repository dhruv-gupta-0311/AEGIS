import { useState, useEffect, useCallback } from 'react'
import { scanHistory, reports } from '../services/api'
import './ScanHistoryPage.css'

const TYPE_LABEL  = { url: 'URL', phishing: 'Email', password: 'Password' }
const RISK_COLOR  = { safe: 'success', low: 'info', medium: 'warning', high: 'danger', critical: 'danger' }
const SEV_COLOR   = { critical: 'var(--danger)', high: '#f0803c', medium: 'var(--warning)', low: 'var(--info)', info: '#8b949e' }

function formatDate(iso) {
  const d = new Date(iso)
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function downloadHtml(scanId) {
  const token = localStorage.getItem('aegis_token')
  const base  = import.meta.env.VITE_API_URL ?? '/api'
  const url   = `${base}/v1/reports/${scanId}/download`
  const a = document.createElement('a')
  a.href = url + '?token=' + encodeURIComponent(token ?? '')
  // Use fetch to include the auth header, then trigger download
  fetch(url, { headers: { Authorization: `Bearer ${token}` } })
    .then(r => r.blob())
    .then(blob => {
      const blobUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = blobUrl
      link.download = `aegis-report-scan-${scanId}.html`
      link.click()
      URL.revokeObjectURL(blobUrl)
    })
    .catch(() => alert('Failed to download report.'))
}

export default function ScanHistoryPage() {
  const [scans,      setScans]      = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [page,       setPage]       = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total,      setTotal]      = useState(0)
  const [filters,    setFilters]    = useState({ scan_type: '', risk_level: '' })
  const [expanded,   setExpanded]   = useState(null)
  const [expandData, setExpandData] = useState({})   // scan_id -> full detail
  const [deleting,   setDeleting]   = useState(null)

  const load = useCallback(() => {
    setLoading(true); setError(null)
    const params = { page, per_page: 20 }
    if (filters.scan_type)  params.scan_type  = filters.scan_type
    if (filters.risk_level) params.risk_level = filters.risk_level
    scanHistory.list(params)
      .then(data => { setScans(data.items); setTotal(data.total); setTotalPages(data.pages); setLoading(false) })
      .catch(err  => { setError(err.message ?? 'Failed to load scan history.'); setLoading(false) })
  }, [page, filters])

  useEffect(() => { load() }, [load])

  async function toggleExpand(id) {
    if (expanded === id) { setExpanded(null); return }
    setExpanded(id)
    if (expandData[id]) return   // already fetched
    try {
      const detail = await scanHistory.getById(id)
      setExpandData(prev => ({ ...prev, [id]: detail }))
    } catch { /* fallback: show whatever we have */ }
  }

  function handleFilterChange(key, value) {
    setFilters(f => ({ ...f, [key]: value })); setPage(1); setExpanded(null)
  }

  async function handleDelete(e, id) {
    e.stopPropagation()
    if (!window.confirm('Delete this scan record?')) return
    setDeleting(id)
    try {
      await scanHistory.deleteById(id)
      setScans(prev => prev.filter(s => s.id !== id))
      setTotal(t => t - 1)
      if (expanded === id) setExpanded(null)
    } catch (err) { alert(err.message ?? 'Delete failed.') }
    finally { setDeleting(null) }
  }

  return (
    <div className="sh-page">
      <div className="sh-header">
        <div>
          <h1 className="sh-title">Scan History</h1>
          <p className="sh-subtitle">
            {loading ? 'Loading...' : total === 0 ? 'No scans on record yet.' : `${total} scan${total !== 1 ? 's' : ''} on record`}
          </p>
        </div>
        <button className="sh-refresh-btn" onClick={load} disabled={loading}>Refresh</button>
      </div>

      <div className="sh-filters">
        <select className="sh-select" value={filters.scan_type} onChange={e => handleFilterChange('scan_type', e.target.value)} aria-label="Filter by type">
          <option value="">All Types</option>
          <option value="url">URL</option>
          <option value="phishing">Email</option>
          <option value="password">Password</option>
        </select>
        <select className="sh-select" value={filters.risk_level} onChange={e => handleFilterChange('risk_level', e.target.value)} aria-label="Filter by risk">
          <option value="">All Risk Levels</option>
          <option value="safe">Safe</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {error && (
        <div className="sh-error" role="alert">
          {error}<button className="sh-error-retry" onClick={load}>Retry</button>
        </div>
      )}

      <div className="sh-table-wrap">
        {loading ? (
          <div className="sh-skeleton">{[...Array(6)].map((_, i) => <div key={i} className="sh-skeleton-row" />)}</div>
        ) : scans.length === 0 ? (
          <div className="sh-empty">{filters.scan_type || filters.risk_level ? 'No scans match your filters.' : 'No scans yet. Run an analysis to see results here.'}</div>
        ) : (
          <table className="sh-table" role="grid">
            <thead>
              <tr><th>Type</th><th>Target</th><th>Risk</th><th>Score</th><th>Date</th><th></th></tr>
            </thead>
            <tbody>
              {scans.map(scan => {
                const color  = RISK_COLOR[scan.risk_level] ?? 'default'
                const isOpen = expanded === scan.id
                const detail = expandData[scan.id]
                return [
                  <tr key={scan.id} className={`sh-row${isOpen ? ' sh-row--open' : ''}`}
                    onClick={() => toggleExpand(scan.id)} role="button" tabIndex={0}
                    onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') toggleExpand(scan.id) }}
                    aria-expanded={isOpen}>
                    <td><span className={`sh-type-badge sh-type-badge--${scan.scan_type}`}>{TYPE_LABEL[scan.scan_type] ?? scan.scan_type}</span></td>
                    <td className="sh-target" title={scan.target}>{scan.target.length > 48 ? scan.target.slice(0, 48) + '...' : scan.target}</td>
                    <td><span className={`sh-risk sh-risk--${color}`}>{scan.risk_level}</span></td>
                    <td className="sh-score">{scan.risk_score}</td>
                    <td className="sh-date">{formatDate(scan.scanned_at)}</td>
                    <td className="sh-actions-cell" onClick={e => e.stopPropagation()}>
                      <button className="sh-download-btn" onClick={() => downloadHtml(scan.id)} title="Download HTML report">Report</button>
                      <button className="sh-delete-btn" onClick={e => handleDelete(e, scan.id)} disabled={deleting === scan.id} title="Delete scan">{deleting === scan.id ? '...' : 'Delete'}</button>
                    </td>
                  </tr>,
                  isOpen && (
                    <tr key={`${scan.id}-detail`} className="sh-detail-row">
                      <td colSpan={6}>
                        <div className="sh-detail">
                          <div className="sh-detail-section">
                            <span className="sh-detail-label">Full target</span>
                            <code className="sh-detail-value">{scan.target}</code>
                          </div>
                          {!detail && <div className="sh-detail-section"><span className="sh-detail-value sh-detail-value--muted">Loading details...</span></div>}
                          {detail && detail.indicators && detail.indicators.length > 0 && (
                            <div className="sh-detail-section">
                              <span className="sh-detail-label">Indicators ({detail.indicators.length})</span>
                              <div className="sh-indicator-cards">
                                {detail.indicators.map((ind, i) => (
                                  <div key={i} className="sh-indicator-card">
                                    <div className="sh-indicator-card-header">
                                      <span className="sh-indicator-sev" style={{ color: SEV_COLOR[ind.severity] ?? '#8b949e', borderColor: SEV_COLOR[ind.severity] ?? '#8b949e' }}>{ind.severity}</span>
                                      <span className="sh-indicator-name">{ind.name}</span>
                                    </div>
                                    <p className="sh-indicator-detail">{ind.detail}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          {detail && (!detail.indicators || detail.indicators.length === 0) && (
                            <div className="sh-detail-section">
                              <span className="sh-detail-label">Indicators</span>
                              <span className="sh-detail-value sh-detail-value--muted">None detected</span>
                            </div>
                          )}
                          {detail && detail.recommendations && detail.recommendations.length > 0 && (
                            <div className="sh-detail-section">
                              <span className="sh-detail-label">Recommendations</span>
                              <ul className="sh-rec-list">
                                {detail.recommendations.map((r, i) => <li key={i}>{r}</li>)}
                              </ul>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                ]
              })}
            </tbody>
          </table>
        )}
      </div>

      {!loading && totalPages > 1 && (
        <div className="sh-pagination">
          <button className="sh-page-btn" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>Previous</button>
          <span className="sh-page-label">Page {page} of {totalPages}</span>
          <button className="sh-page-btn" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>Next</button>
        </div>
      )}
    </div>
  )
}
