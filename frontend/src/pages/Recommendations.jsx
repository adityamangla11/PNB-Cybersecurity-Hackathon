import { useState, useEffect } from 'react';
import { getRecommendations } from '../api/client';
import { useToast } from '../components/Toast';
import LabelBadge from '../components/LabelBadge';

const PRIORITY_STYLES = {
  Critical: 'border-red-500 bg-red-950/30',
  High: 'border-amber-500 bg-amber-950/30',
  Medium: 'border-blue-500 bg-blue-950/30',
  Low: 'border-gray-500 bg-gray-950/30',
};

export default function Recommendations() {
  const [recs, setRecs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterPriority, setFilterPriority] = useState('All');
  const toast = useToast();

  useEffect(() => {
    getRecommendations()
      .then(res => setRecs(res.data))
      .catch((err) => toast(err.response?.data?.detail || 'Failed to load recommendations', 'error'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = filterPriority === 'All' ? recs : recs.filter(r => r.priority === filterPriority);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">PQC Migration Recommendations</h1>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Filter:</span>
          {['All', 'Critical', 'High', 'Medium', 'Low'].map(p => (
            <button
              key={p}
              onClick={() => setFilterPriority(p)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${filterPriority === p ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {['Critical', 'High', 'Medium', 'Low'].map(p => {
          const count = recs.filter(r => r.priority === p).length;
          return (
            <div key={p} className={`rounded-lg border p-3 ${PRIORITY_STYLES[p]}`}>
              <p className="text-xs text-gray-400">{p} Priority</p>
              <p className="text-2xl font-bold text-white">{count}</p>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && <p className="text-gray-400 text-center mt-8">No recommendations. {recs.length === 0 ? 'Run a scan first.' : 'All clear for this filter!'}</p>}

      {/* Recommendation Cards */}
      <div className="space-y-3">
        {filtered.map((rec, i) => (
          <div key={i} className={`border-l-4 rounded-r-xl bg-gray-800 border-y border-r border-gray-700 p-5 ${PRIORITY_STYLES[rec.priority]?.split(' ')[0] || 'border-gray-500'}`}>
            <div className="flex items-start justify-between mb-2">
              <div>
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${rec.priority === 'Critical' ? 'bg-red-600 text-white' : rec.priority === 'High' ? 'bg-amber-600 text-white' : rec.priority === 'Medium' ? 'bg-blue-600 text-white' : 'bg-gray-600 text-white'}`}>
                  {rec.priority}
                </span>
                <span className="text-xs text-gray-500 ml-3">{rec.affected_component}</span>
              </div>
              <div className="text-right">
                <p className="text-xs text-gray-400 font-mono">{rec.asset_host}:{rec.asset_port}</p>
                <LabelBadge label={rec.asset_label} />
              </div>
            </div>

            <div className="mt-3 flex items-center gap-3">
              <div className="bg-red-900/40 rounded px-3 py-1.5 text-xs text-red-300 font-mono">{rec.current}</div>
              <span className="text-gray-500">→</span>
              <div className="bg-emerald-900/40 rounded px-3 py-1.5 text-xs text-emerald-300 font-mono">{rec.recommended}</div>
            </div>

            <p className="text-sm text-gray-300 mt-3">{rec.rationale}</p>
            <p className="text-sm text-blue-400 mt-2"><strong>Action:</strong> {rec.action}</p>
            <p className="text-xs text-gray-500 mt-1">Standard: {rec.standard}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
