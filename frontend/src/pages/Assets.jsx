import { useState, useEffect } from 'react';
import { listAssets, getAsset, getBadgeUrl } from '../api/client';
import { useToast } from '../components/Toast';
import LabelBadge from '../components/LabelBadge';

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const toast = useToast();

  useEffect(() => {
    listAssets()
      .then(res => setAssets(res.data))
      .catch((err) => toast(err.response?.data?.detail || 'Failed to load assets', 'error'))
      .finally(() => setLoading(false));
  }, []);

  const openDetail = async (id) => {
    const res = await getAsset(id);
    setDetail(res.data);
    setSelected(id);
  };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Crypto Asset Inventory</h1>

      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-gray-400 border-b border-gray-700 bg-gray-800/80">
              <tr>
                <th className="py-3 px-4">Host</th>
                <th className="py-3 px-4">Port</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">TLS Version</th>
                <th className="py-3 px-4">Key Type</th>
                <th className="py-3 px-4">Key Size</th>
                <th className="py-3 px-4">Cert Expiry</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Label</th>
              </tr>
            </thead>
            <tbody className="text-gray-300">
              {assets.length === 0 && (
                <tr><td colSpan={9} className="text-center py-8 text-gray-500">No assets discovered yet. Run a scan first.</td></tr>
              )}
              {assets.map(asset => (
                <tr key={asset.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer" onClick={() => openDetail(asset.id)}>
                  <td className="py-2.5 px-4 font-mono text-blue-400">{asset.host}</td>
                  <td className="py-2.5 px-4">{asset.port}</td>
                  <td className="py-2.5 px-4 capitalize">{asset.asset_type?.replace('_', ' ')}</td>
                  <td className="py-2.5 px-4">{asset.highest_tls_version || '—'}</td>
                  <td className="py-2.5 px-4">{asset.cert_key_type || '—'}</td>
                  <td className="py-2.5 px-4">{asset.cert_key_size || '—'}</td>
                  <td className="py-2.5 px-4">{asset.cert_not_after ? new Date(asset.cert_not_after).toLocaleDateString() : '—'}</td>
                  <td className="py-2.5 px-4">
                    <span className={`font-bold ${asset.score >= 90 ? 'text-emerald-400' : asset.score >= 60 ? 'text-blue-400' : asset.score >= 30 ? 'text-amber-400' : 'text-red-400'}`}>
                      {asset.score}
                    </span>
                  </td>
                  <td className="py-2.5 px-4"><LabelBadge label={asset.label} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Panel */}
      {detail && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => { setSelected(null); setDetail(null); }}>
          <div className="bg-gray-800 border border-gray-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white">{detail.host}:{detail.port}</h2>
              <div className="flex items-center gap-3">
                <a href={getBadgeUrl(detail.id)} target="_blank" rel="noopener noreferrer" className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-medium transition-colors">
                  Download Badge
                </a>
                <button onClick={() => { setSelected(null); setDetail(null); }} className="text-gray-400 hover:text-white text-2xl">&times;</button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-6">
              <div>
                <p className="text-gray-400 text-xs">Score</p>
                <p className={`text-2xl font-bold ${detail.score >= 90 ? 'text-emerald-400' : detail.score >= 60 ? 'text-blue-400' : detail.score >= 30 ? 'text-amber-400' : 'text-red-400'}`}>{detail.score}</p>
              </div>
              <div>
                <p className="text-gray-400 text-xs">Label</p>
                <LabelBadge label={detail.label} />
              </div>
            </div>

            {/* TLS Versions */}
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-1">TLS Versions Supported</h3>
              <div className="flex gap-2">
                {(detail.tls_versions || []).map(v => (
                  <span key={v} className={`px-2 py-0.5 rounded text-xs ${v === 'TLS 1.3' ? 'bg-emerald-900 text-emerald-300' : v === 'TLS 1.2' ? 'bg-blue-900 text-blue-300' : 'bg-red-900 text-red-300'}`}>{v}</span>
                ))}
              </div>
            </div>

            {/* Certificate */}
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-1">Certificate Details</h3>
              <div className="bg-gray-900 rounded p-3 text-xs text-gray-400 space-y-1 font-mono">
                <p>Subject: {detail.cert_subject || '—'}</p>
                <p>Issuer: {detail.cert_issuer || '—'}</p>
                <p>Key: {detail.cert_key_type} ({detail.cert_key_size} bits)</p>
                <p>Signature: {detail.cert_signature_algorithm || '—'}</p>
                <p>Expires: {detail.cert_not_after ? new Date(detail.cert_not_after).toLocaleDateString() : '—'}</p>
              </div>
            </div>

            {/* Cipher Suites */}
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-1">Cipher Suites</h3>
              <div className="bg-gray-900 rounded p-3 space-y-1">
                {(detail.cipher_suites || []).map((s, i) => (
                  <p key={i} className="text-xs font-mono text-gray-400">{s.name} ({s.protocol}, {s.bits} bits)</p>
                ))}
              </div>
            </div>

            {/* Key Exchange */}
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-1">Key Exchange Algorithms</h3>
              <div className="flex gap-2 flex-wrap">
                {(detail.key_exchange_algorithms || []).map(k => (
                  <span key={k} className="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-300">{k}</span>
                ))}
              </div>
            </div>

            {/* Classification */}
            {detail.classification_details?.vulnerabilities?.length > 0 && (
              <div className="mb-4">
                <h3 className="text-sm font-semibold text-red-400 mb-1">Vulnerabilities</h3>
                <ul className="list-disc list-inside text-xs text-red-300 space-y-0.5">
                  {detail.classification_details.vulnerabilities.map((v, i) => <li key={i}>{v}</li>)}
                </ul>
              </div>
            )}

            {/* Recommendations */}
            {detail.recommendations?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-amber-400 mb-1">Recommendations</h3>
                <div className="space-y-2">
                  {detail.recommendations.map((r, i) => (
                    <div key={i} className="bg-gray-900 rounded p-3 border-l-2 border-amber-500">
                      <p className="text-xs font-semibold text-white">{r.current} → {r.recommended}</p>
                      <p className="text-xs text-gray-400 mt-0.5">{r.action}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{r.standard}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
