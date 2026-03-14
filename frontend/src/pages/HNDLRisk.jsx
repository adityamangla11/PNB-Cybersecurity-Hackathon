import { useState, useEffect } from 'react';
import { getHNDLSummary } from '../api/client';

const URGENCY_COLORS = {
  IMMEDIATE: 'bg-red-900 text-red-300 border-red-700',
  URGENT: 'bg-amber-900 text-amber-300 border-amber-700',
  'PLAN NOW': 'bg-blue-900 text-blue-300 border-blue-700',
  MONITOR: 'bg-emerald-900 text-emerald-300 border-emerald-700',
};

const RISK_BAR_COLORS = {
  critical: 'bg-red-500',
  high: 'bg-amber-500',
  medium: 'bg-blue-500',
  low: 'bg-emerald-500',
};

export default function HNDLRisk() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    getHNDLSummary()
      .then(res => setData(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>;

  if (data.length === 0) return <p className="text-gray-400 text-center mt-10">No data. Run a scan first.</p>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">HNDL Risk Timeline</h1>
        <p className="text-sm text-gray-400 mt-1">Harvest Now, Decrypt Later — when could intercepted data be decrypted by quantum computers?</p>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {['critical', 'high', 'medium', 'low'].map(level => {
          const count = data.filter(d => d.risk_level === level).length;
          const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
          const colors = { critical: 'text-red-400', high: 'text-amber-400', medium: 'text-blue-400', low: 'text-emerald-400' };
          return (
            <div key={level} className="bg-gray-800 border border-gray-700 rounded-xl p-4 text-center">
              <p className={`text-3xl font-bold ${colors[level]}`}>{count}</p>
              <p className="text-xs text-gray-400 uppercase mt-1">{labels[level]} Risk</p>
            </div>
          );
        })}
      </div>

      {/* Asset Risk Cards */}
      {data.map((item, idx) => (
        <div key={idx} className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-700/30" onClick={() => setExpanded(expanded === idx ? null : idx)}>
            <div className="flex items-center gap-4">
              <div className={`w-3 h-3 rounded-full ${RISK_BAR_COLORS[item.risk_level] || 'bg-gray-500'}`}></div>
              <div>
                <span className="text-white font-mono font-semibold">{item.host}:{item.port}</span>
                <span className="text-gray-500 text-sm ml-3">Score: {item.score}</span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {item.urgency && (
                <span className={`px-3 py-1 rounded-lg text-xs font-bold border ${URGENCY_COLORS[item.urgency] || 'bg-gray-700'}`}>
                  {item.urgency}
                </span>
              )}
              {item.earliest_risk_year && (
                <span className="text-gray-400 text-sm">Risk by <span className="text-white font-semibold">{item.earliest_risk_year}</span></span>
              )}
              <span className="text-gray-500">{expanded === idx ? '▲' : '▼'}</span>
            </div>
          </div>

          {/* Expanded Detail */}
          {expanded === idx && (
            <div className="border-t border-gray-700 p-4 space-y-4">
              {/* Summary */}
              <p className="text-sm text-gray-300">{item.summary}</p>

              {/* Timeline Bar */}
              {item.earliest_risk_year && (
                <div className="bg-gray-900 rounded-lg p-4">
                  <h4 className="text-xs text-gray-400 uppercase mb-3">Quantum Threat Timeline</h4>
                  <div className="relative h-8 bg-gray-700 rounded-full overflow-hidden">
                    <div className="absolute left-0 top-0 h-full bg-emerald-600/50 rounded-l-full" style={{ width: `${Math.max(5, ((item.earliest_risk_year - 2026) / 20) * 100)}%` }}></div>
                    <div className="absolute left-0 top-0 h-full bg-red-600/30 rounded-r-full" style={{ left: `${Math.max(5, ((item.earliest_risk_year - 2026) / 20) * 100)}%`, width: `${100 - Math.max(5, ((item.earliest_risk_year - 2026) / 20) * 100)}%` }}></div>
                  </div>
                  <div className="flex justify-between mt-2 text-xs text-gray-400">
                    <span>2026 (Now)</span>
                    <span className="text-amber-400 font-semibold">Earliest: {item.earliest_risk_year}</span>
                    <span className="text-red-400 font-semibold">Likely: {item.likely_risk_year}</span>
                    <span>2046</span>
                  </div>
                </div>
              )}

              {/* Vulnerable Components */}
              {item.risks?.length > 0 && (
                <div>
                  <h4 className="text-xs text-gray-400 uppercase mb-2">Vulnerable Components</h4>
                  <div className="space-y-2">
                    {item.risks.map((r, i) => (
                      <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                        <div>
                          <p className="text-sm text-white font-medium">{r.component}</p>
                          <p className="text-xs text-gray-500">{r.attack}</p>
                        </div>
                        <div className="text-right">
                          <p className="text-sm text-amber-400 font-semibold">{r.years_until_risk_earliest} years</p>
                          <p className="text-xs text-gray-500">until earliest risk</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Data Exposure Scenarios */}
              {item.data_exposure_scenarios?.length > 0 && (
                <div>
                  <h4 className="text-xs text-gray-400 uppercase mb-2">Banking Data Exposure Scenarios</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {item.data_exposure_scenarios.map((s, i) => (
                      <div key={i} className={`rounded-lg p-3 border text-sm ${s.at_risk ? 'bg-red-900/20 border-red-800' : 'bg-emerald-900/20 border-emerald-800'}`}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium text-white">{s.data_type}</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-bold ${s.at_risk ? 'bg-red-900 text-red-300' : 'bg-emerald-900 text-emerald-300'}`}>
                            {s.at_risk ? `${s.exposure_window_years}yr exposure` : 'Safe'}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400">{s.narrative}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
