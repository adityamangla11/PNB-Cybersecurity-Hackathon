import { useState, useEffect } from 'react';
import { getDashboardSummary } from '../api/client';
import { useToast } from '../components/Toast';
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import ScoreCard from '../components/ScoreCard';
import LabelBadge from '../components/LabelBadge';

const PIE_COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#dc2626'];

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  useEffect(() => {
    getDashboardSummary()
      .then(res => setSummary(res.data))
      .catch((err) => toast(err.response?.data?.detail || 'Failed to load dashboard. Is the backend running?', 'error'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>;
  if (!summary) return <p className="text-gray-400 text-center mt-10">No data yet. Start a scan to see results.</p>;

  const pieData = [
    { name: 'PQC Ready', value: summary.pqc_ready },
    { name: 'Quantum-Safe', value: summary.quantum_safe },
    { name: 'At Risk', value: summary.at_risk },
    { name: 'Critical', value: summary.critical },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Dashboard Overview</h1>

      {/* Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <ScoreCard title="Total Assets" value={summary.total_assets} icon="shield" color="purple" />
        <ScoreCard title="PQC Ready" value={summary.pqc_ready} icon="shield-check" color="green" />
        <ScoreCard title="At Risk" value={summary.at_risk} icon="shield-alert" color="yellow" />
        <ScoreCard title="Critical" value={summary.critical} icon="shield-x" color="red" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Label Distribution */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Quantum Readiness Distribution</h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={100} dataKey="value" label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}>
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff' }} />
                <Legend wrapperStyle={{ color: '#9ca3af' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-400 text-center py-10">No data available</p>}
        </div>

        {/* Score Trend Over Time */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Score Variation Over Time</h2>
          {summary.score_trend.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={summary.score_trend}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" stroke="#9ca3af" tick={{ fontSize: 11 }} tickFormatter={(val) => new Date(val).toLocaleDateString()} />
                <YAxis domain={[0, 100]} stroke="#9ca3af" />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '8px', color: '#fff' }} labelFormatter={(val) => new Date(val).toLocaleString()} />
                <Line type="monotone" dataKey="avg_score" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4, fill: '#3b82f6' }} name="Avg Score" />
              </LineChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-400 text-center py-10">Run multiple scans to see trends</p>}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
        {summary.recent_scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-gray-400 border-b border-gray-700">
                <tr>
                  <th className="py-2 px-3">Scan ID</th>
                  <th className="py-2 px-3">Date</th>
                  <th className="py-2 px-3">Status</th>
                  <th className="py-2 px-3">Targets</th>
                  <th className="py-2 px-3">Progress</th>
                </tr>
              </thead>
              <tbody className="text-gray-300">
                {summary.recent_scans.map(scan => (
                  <tr key={scan.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td className="py-2 px-3 font-mono">#{scan.id}</td>
                    <td className="py-2 px-3">{new Date(scan.created_at).toLocaleString()}</td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${scan.status === 'completed' ? 'bg-emerald-900 text-emerald-300' : scan.status === 'running' ? 'bg-blue-900 text-blue-300' : scan.status === 'failed' ? 'bg-red-900 text-red-300' : 'bg-gray-700 text-gray-300'}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-2 px-3">{scan.total_targets}</td>
                    <td className="py-2 px-3">{scan.completed_targets}/{scan.total_targets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="text-gray-400">No scans yet</p>}
      </div>
    </div>
  );
}
