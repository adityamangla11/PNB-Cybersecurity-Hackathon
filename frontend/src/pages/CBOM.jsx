import { useState, useEffect } from 'react';
import { listScans, getCBOM } from '../api/client';
import { Download } from 'lucide-react';

export default function CBOM() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [cbomData, setCbomData] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    listScans().then(res => {
      const completed = res.data.filter(s => s.status === 'completed');
      setScans(completed);
      if (completed.length > 0) loadCBOM(completed[0].id);
    }).catch(() => {});
  }, []);

  const loadCBOM = async (scanId) => {
    setSelectedScan(scanId);
    setLoading(true);
    try {
      const res = await getCBOM(scanId);
      setCbomData(res.data);
    } catch {
      setCbomData(null);
    } finally {
      setLoading(false);
    }
  };

  const downloadCBOM = () => {
    if (!cbomData) return;
    const blob = new Blob([JSON.stringify(cbomData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom_scan_${selectedScan}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Cryptographic Bill of Materials</h1>
        {cbomData && (
          <button onClick={downloadCBOM} className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-sm font-medium transition-colors">
            <Download className="w-4 h-4" /> Export CBOM JSON
          </button>
        )}
      </div>

      {/* Scan Selector */}
      {scans.length > 0 && (
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Select Scan:</label>
          <select
            className="bg-gray-800 border border-gray-600 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
            value={selectedScan || ''}
            onChange={e => loadCBOM(Number(e.target.value))}
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>Scan #{s.id} — {new Date(s.created_at).toLocaleString()}</option>
            ))}
          </select>
        </div>
      )}

      {loading && <div className="flex items-center justify-center h-32"><div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-400"></div></div>}

      {!loading && !cbomData && <p className="text-gray-400 text-center mt-8">No CBOM data. Complete a scan first.</p>}

      {cbomData && (
        <div className="space-y-4">
          {/* Metadata */}
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
            <h2 className="text-lg font-semibold text-white mb-3">CBOM Metadata</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div><p className="text-gray-400">Format</p><p className="text-white font-mono">{cbomData.bomFormat}</p></div>
              <div><p className="text-gray-400">Spec Version</p><p className="text-white font-mono">{cbomData.specVersion}</p></div>
              <div><p className="text-gray-400">Components</p><p className="text-white font-mono">{cbomData.components?.length || 0}</p></div>
              <div><p className="text-gray-400">Vulnerabilities</p><p className="text-red-400 font-mono">{cbomData.vulnerabilities?.length || 0}</p></div>
            </div>
          </div>

          {/* Components Tree */}
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
            <h2 className="text-lg font-semibold text-white mb-3">Crypto Components</h2>
            <div className="space-y-3">
              {(cbomData.components || []).map((comp, i) => (
                <details key={i} className="bg-gray-900 rounded-lg border border-gray-700">
                  <summary className="px-4 py-3 cursor-pointer text-sm font-medium text-blue-400 hover:text-blue-300">
                    {comp.name} <span className="text-gray-500 ml-2">({comp.version})</span>
                  </summary>
                  <div className="px-4 pb-3 pt-1">
                    <p className="text-xs text-gray-400 mb-2">{comp.description}</p>
                    <div className="grid grid-cols-1 gap-1">
                      {(comp.properties || []).map((prop, j) => (
                        <div key={j} className="flex gap-2 text-xs">
                          <span className="text-gray-500 font-mono min-w-[180px]">{prop.name}</span>
                          <span className={`font-mono ${prop.name.includes('vulnerability') ? 'text-red-400' : prop.name.includes('quantum:label') ? 'text-amber-400' : 'text-gray-300'}`}>{prop.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </details>
              ))}
            </div>
          </div>

          {/* Raw JSON Preview */}
          <details className="bg-gray-800 border border-gray-700 rounded-xl">
            <summary className="px-5 py-3 cursor-pointer text-sm font-medium text-gray-400 hover:text-white">Raw CycloneDX JSON</summary>
            <pre className="p-5 text-xs font-mono text-gray-400 overflow-x-auto max-h-96 overflow-y-auto">{JSON.stringify(cbomData, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  );
}
