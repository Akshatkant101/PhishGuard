const API_BASE = '/v1';

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const response = await fetch(url, { ...options, headers });
  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch (_) {}
    throw new Error(errorDetail || `HTTP ${response.status}`);
  }

  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export const api = {
  // Scans
  scanUrl: (url) => request('/scan', { method: 'POST', body: JSON.stringify({ url }) }),
  scanBatch: (urls) => request('/scan/batch', { method: 'POST', body: JSON.stringify({ urls }) }),
  getScanById: (id) => request(`/scan/${id}`),

  // History
  getHistory: ({ search, verdict, limit = 50, offset = 0 } = {}) => {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (verdict && verdict !== 'ALL') params.append('verdict', verdict);
    params.append('limit', limit);
    params.append('offset', offset);
    return request(`/history?${params.toString()}`);
  },
  getExportCsvUrl: (verdict) => {
    const params = new URLSearchParams();
    if (verdict && verdict !== 'ALL') params.append('verdict', verdict);
    return `${API_BASE}/history/export?${params.toString()}`;
  },

  // Blocklist
  getBlocklist: () => request('/blocklist'),
  addBlocklist: (pattern, entry_type = 'domain', reason = '') =>
    request('/blocklist', {
      method: 'POST',
      body: JSON.stringify({ pattern, entry_type, reason }),
    }),
  deleteBlocklist: (id) => request(`/blocklist/${id}`, { method: 'DELETE' }),

  // Allowlist
  getAllowlist: () => request('/allowlist'),
  addAllowlist: (pattern, entry_type = 'domain', reason = '') =>
    request('/allowlist', {
      method: 'POST',
      body: JSON.stringify({ pattern, entry_type, reason }),
    }),
  deleteAllowlist: (id) => request(`/allowlist/${id}`, { method: 'DELETE' }),

  // System
  getHealth: () => request('/health'),
  getModelInfo: () => request('/model'),
};
