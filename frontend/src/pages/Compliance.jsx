import { useState, useEffect } from 'react';
import { getComplianceSummary } from '../api/client';

const STATUS_STYLES = {
  'compliant': 'bg-emerald-900 text-emerald-300',
  'non-compliant': 'bg-red-900 text-red-300',
  'needs-attention': 'bg-amber-900 text-amber-300',
  'unknown': 'bg-gray-700 text-gray-300',
};

const FW_COLORS = {
  RBI: '#f59e0b',
  PCI_DSS: '#3b82f6',
  NIST_CSF: '#10b981',
  CERT_IN: '#a855f7',
};

export default function Compliance() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState(null);

  useEffect(() => {
    getComplianceSummary()
      .then(res => setData(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>;
  if (!data || !data.frameworks || Object.keys(data.frameworks).length === 0) return <p className="text-gray-400 text-center mt-10">No compliance data. Run a scan first.</p>;

  const asset = selectedAsset !== null ? data.assets[selectedAsset] : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Regulatory Compliance</h1>
        <p className="text-sm text-gray-400 mt-1">Mapping crypto findings to RBI, PCI-DSS, NIST, and CERT-In requirements</p>
      </div>

      {/* Framework Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {Object.entries(data.frameworks).map(([id, fw]) => (
          <div key={id} className="bg-gray-800 border border-gray-700 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: FW_COLORS[id] || '#6b7280' }}></div>
              <h3 className="text-sm font-semibold text-white">{fw.name}</h3>
            </div>
            <div className="relative h-3 bg-gray-700 rounded-full mb-2">
              <div className="absolute h-full rounded-full transition-all" style={{
                width: `${fw.avg_compliance_percentage}%`,
                backgroundColor: fw.avg_compliance_percentage >= 75 ? '#10b981' : fw.avg_compliance_percentage >= 50 ? '#f59e0b' : '#dc2626',
              }}></div>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-gray-400">{fw.asset_count} assets</span>
              <span className={`font-bold ${fw.avg_compliance_percentage >= 75 ? 'text-emerald-400' : fw.avg_compliance_percentage >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                {fw.avg_compliance_percentage}%
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Per-Asset Compliance */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Per-Asset Compliance</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-gray-400 border-b border-gray-700">
              <tr>
                <th className="py-2 px-3">Asset</th>
                {Object.keys(data.frameworks).map(id => (
                  <th key={id} className="py-2 px-3">{data.frameworks[id].name}</th>
                ))}
                <th className="py-2 px-3">Details</th>
              </tr>
            </thead>
            <tbody className="text-gray-300">
              {data.assets.map((item, idx) => (
                <tr key={idx} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 px-3 font-mono text-blue-400">{item.host}:{item.port}</td>
                  {Object.keys(data.frameworks).map(fwId => {
                    const c = item.compliance[fwId];
                    return (
                      <td key={fwId} className="py-2 px-3">
                        <span className={`font-bold ${c.compliance_percentage >= 75 ? 'text-emerald-400' : c.compliance_percentage >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                          {c.compliance_percentage}%
                        </span>
                        <span className="text-gray-500 text-xs ml-1">({c.compliant_count}/{c.total_count})</span>
                      </td>
                    );
                  })}
                  <td className="py-2 px-3">
                    <button onClick={() => setSelectedAsset(selectedAsset === idx ? null : idx)} className="text-blue-400 hover:text-blue-300 text-xs underline">
                      {selectedAsset === idx ? 'Hide' : 'View'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Asset Detail */}
      {asset && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">{asset.host}:{asset.port} — Detailed Compliance</h2>
          <div className="space-y-6">
            {Object.entries(asset.compliance).map(([fwId, fw]) => (
              <div key={fwId}>
                <div className="flex items-center gap-2 mb-3">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: FW_COLORS[fwId] || '#6b7280' }}></div>
                  <h3 className="text-sm font-semibold text-gray-300">{fw.full_name}</h3>
                  <span className={`ml-auto px-2 py-0.5 rounded text-xs font-bold ${fw.compliance_percentage >= 75 ? 'bg-emerald-900 text-emerald-300' : fw.compliance_percentage >= 50 ? 'bg-amber-900 text-amber-300' : 'bg-red-900 text-red-300'}`}>
                    {fw.compliance_percentage}%
                  </span>
                </div>
                <div className="space-y-2">
                  {fw.requirements.map((req, i) => (
                    <div key={i} className={`bg-gray-900 rounded-lg p-3 border-l-3 ${req.status === 'compliant' ? 'border-l-emerald-500' : req.status === 'non-compliant' ? 'border-l-red-500' : 'border-l-amber-500'}`}>
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <p className="text-xs text-gray-400 font-mono">{req.clause}</p>
                          <p className="text-sm text-gray-300 mt-1">{req.requirement}</p>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ml-3 whitespace-nowrap ${STATUS_STYLES[req.status]}`}>
                          {req.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
