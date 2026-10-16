import React, { useState, useEffect } from 'react';
import { Search, Download, RefreshCw, X } from 'lucide-react';
import { api } from '../api/client';
import VerdictBadge from '../components/VerdictBadge';
import ScanResultCard from '../components/ScanResultCard';

const VERDICTS = ['ALL', 'SAFE', 'SUSPICIOUS', 'PHISHING'];

export default function HistoryPage() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [selectedScan, setSelectedScan] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory({
        search: search.trim(),
        verdict: verdictFilter,
        limit: 100,
      });
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [verdictFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHistory();
  };

  return (
    <div className="animate-fade">
      {/* Controls Header */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '12px',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: '20px',
        }}
      >
        {/* Search */}
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '8px', flex: '1', minWidth: '240px', maxWidth: '400px' }}>
          <input
            type="text"
            placeholder="Search domain or URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-text mono"
            style={{ padding: '6px 12px', fontSize: '13px' }}
          />
          <button type="submit" className="btn btn-secondary btn-sm">
            <Search size={14} />
          </button>
        </form>

        {/* Verdict filter tabs & CSV export */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <div className="nav-tabs">
            {VERDICTS.map((v) => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`nav-tab mono ${verdictFilter === v ? 'active' : ''}`}
                style={{ fontSize: '11px', padding: '4px 10px' }}
              >
                {v}
              </button>
            ))}
          </div>

          <button onClick={fetchHistory} className="btn btn-secondary btn-sm" title="Refresh">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>

          <a
            href={api.getExportCsvUrl(verdictFilter)}
            download
            className="btn btn-secondary btn-sm mono"
          >
            <Download size={13} />
            <span>EXPORT CSV</span>
          </a>
        </div>
      </div>

      {/* History Table */}
      <div className="table-container">
        <table className="minimal-table">
          <thead>
            <tr>
              <th style={{ width: '60px' }}>ID</th>
              <th style={{ width: '120px' }}>Verdict</th>
              <th style={{ width: '90px' }}>Risk</th>
              <th>Domain / URL</th>
              <th style={{ width: '90px' }}>Latency</th>
              <th style={{ width: '160px' }}>Timestamp</th>
              <th style={{ width: '80px', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {history.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  {loading ? 'Loading scan history...' : 'No scan records found.'}
                </td>
              </tr>
            ) : (
              history.map((item) => (
                <tr key={item.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedScan(item)}>
                  <td className="mono text-muted">#{item.id}</td>
                  <td>
                    <VerdictBadge verdict={item.verdict} />
                  </td>
                  <td className="mono" style={{ fontWeight: 600 }}>
                    {item.risk_score}
                  </td>
                  <td>
                    <div className="mono" style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                      {item.domain}
                    </div>
                    <div
                      className="mono text-muted"
                      style={{
                        fontSize: '11px',
                        maxWidth: '400px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {item.url}
                    </div>
                  </td>
                  <td className="mono text-muted">{item.latency_ms} ms</td>
                  <td className="mono text-secondary" style={{ fontSize: '11px' }}>
                    {item.created_at ? new Date(item.created_at).toLocaleString() : '-'}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedScan(item);
                      }}
                      className="btn btn-secondary btn-sm mono"
                      style={{ fontSize: '11px', padding: '2px 8px' }}
                    >
                      VIEW
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {selectedScan && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
          onClick={() => setSelectedScan(null)}
        >
          <div
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-md)',
              width: '100%',
              maxWidth: '800px',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '24px',
              position: 'relative',
            }}
            onClick={(e) => e.stopPropagation()}
            className="animate-fade"
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <span className="card-title">SCAN DETAILS #{selectedScan.id}</span>
              <button onClick={() => setSelectedScan(null)} className="btn btn-secondary btn-icon">
                <X size={16} />
              </button>
            </div>
            <ScanResultCard result={selectedScan} />
          </div>
        </div>
      )}
    </div>
  );
}
