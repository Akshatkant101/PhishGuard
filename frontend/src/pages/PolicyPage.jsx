import React, { useState, useEffect } from 'react';
import { Plus, Trash2, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';

export default function PolicyPage() {
  const [tab, setTab] = useState('blocklist'); // 'blocklist' | 'allowlist'
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pattern, setPattern] = useState('');
  const [entryType, setEntryType] = useState('domain');
  const [reason, setReason] = useState('');
  const [error, setError] = useState(null);

  const fetchItems = async () => {
    setLoading(true);
    setError(null);
    try {
      if (tab === 'blocklist') {
        const data = await api.getBlocklist();
        setItems(data);
      } else {
        const data = await api.getAllowlist();
        setItems(data);
      }
    } catch (err) {
      setError(err.message || 'Failed to load policy rules');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
  }, [tab]);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!pattern.trim()) return;

    setError(null);
    try {
      if (tab === 'blocklist') {
        await api.addBlocklist(pattern.trim(), entryType, reason.trim());
      } else {
        await api.addAllowlist(pattern.trim(), entryType, reason.trim());
      }
      setPattern('');
      setReason('');
      fetchItems();
    } catch (err) {
      setError(err.message || 'Failed to add rule');
    }
  };

  const handleDelete = async (id) => {
    try {
      if (tab === 'blocklist') {
        await api.deleteBlocklist(id);
      } else {
        await api.deleteAllowlist(id);
      }
      setItems(items.filter((i) => i.id !== id));
    } catch (err) {
      setError(err.message || 'Failed to delete rule');
    }
  };

  return (
    <div className="animate-fade">
      {/* Sub tabs */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div className="nav-tabs">
          <button
            onClick={() => setTab('blocklist')}
            className={`nav-tab mono ${tab === 'blocklist' ? 'active' : ''}`}
          >
            BLOCKLIST ({tab === 'blocklist' ? items.length : '...'})
          </button>
          <button
            onClick={() => setTab('allowlist')}
            className={`nav-tab mono ${tab === 'allowlist' ? 'active' : ''}`}
          >
            ALLOWLIST ({tab === 'allowlist' ? items.length : '...'})
          </button>
        </div>

        <span className="mono text-muted" style={{ fontSize: '11px' }}>
          POLICY_RULES_ENGINE
        </span>
      </div>

      {/* Add Rule Form */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">
            ADD NEW {tab.toUpperCase()} RULE
          </span>
        </div>
        <form onSubmit={handleAdd}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 2fr auto', gap: '10px', alignItems: 'center' }}>
            <input
              type="text"
              placeholder={entryType === 'domain' ? 'Domain (e.g., evil-phish.com)' : 'URL pattern...'}
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              className="input-text mono"
              required
            />
            <select
              value={entryType}
              onChange={(e) => setEntryType(e.target.value)}
              className="input-text mono"
              style={{ backgroundColor: 'var(--bg-card)' }}
            >
              <option value="domain">DOMAIN</option>
              <option value="url">FULL URL</option>
            </select>
            <input
              type="text"
              placeholder="Reason / ticket reference..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="input-text"
            />
            <button type="submit" className="btn btn-primary" disabled={!pattern.trim()}>
              <Plus size={14} />
              <span>ADD</span>
            </button>
          </div>
        </form>
      </div>

      {error && (
        <div
          className="card mono"
          style={{
            marginBottom: '20px',
            borderColor: '#ffffff',
            color: '#ffffff',
            backgroundColor: 'var(--bg-secondary)',
            fontSize: '13px',
          }}
        >
          [ERROR]: {error}
        </div>
      )}

      {/* Rules Table */}
      <div className="table-container">
        <table className="minimal-table">
          <thead>
            <tr>
              <th style={{ width: '60px' }}>ID</th>
              <th>Pattern</th>
              <th style={{ width: '100px' }}>Type</th>
              <th>Reason</th>
              <th style={{ width: '120px' }}>Added By</th>
              <th style={{ width: '160px' }}>Created</th>
              <th style={{ width: '60px', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  {loading ? 'Loading rules...' : `No rules configured in ${tab}.`}
                </td>
              </tr>
            ) : (
              items.map((item) => (
                <tr key={item.id}>
                  <td className="mono text-muted">#{item.id}</td>
                  <td className="mono" style={{ fontWeight: 600 }}>
                    {item.pattern}
                  </td>
                  <td>
                    <span className="badge badge-tag mono" style={{ fontSize: '10px' }}>
                      {item.entry_type}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {item.reason || '-'}
                  </td>
                  <td>
                    <span
                      className="mono"
                      style={{
                        fontSize: '11px',
                        border: '1px solid ' + (item.added_by === 'auto-block' ? '#ffffff' : 'var(--border-strong)'),
                        padding: '2px 6px',
                        borderRadius: '2px',
                        color: item.added_by === 'auto-block' ? '#ffffff' : 'var(--text-muted)',
                      }}
                    >
                      {item.added_by}
                    </span>
                  </td>
                  <td className="mono text-secondary" style={{ fontSize: '11px' }}>
                    {new Date(item.created_at).toLocaleString()}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      onClick={() => handleDelete(item.id)}
                      className="btn btn-secondary btn-icon"
                      title="Delete rule"
                    >
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
