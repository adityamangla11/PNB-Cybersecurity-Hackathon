import { useState, useEffect, useRef } from 'react';
import { startScan, startScanCSV, listScans, getScan, getReportUrl } from '../api/client';
import { useToast } from '../components/Toast';

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState('');
  const [scanning, setScanning] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const pollRef = useRef(null);
  const toast = useToast();

  const loadScans = () => listScans().then(res => setScans(res.data)).catch((err) => toast(err.response?.data?.detail || 'Failed to load scans', 'error'));

  useEffect(() => {
    loadScans();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const handleScan = async () => {
    const targetList = targets.split('\n').map(t => t.trim()).filter(Boolean);
    if (targetList.length === 0) return;

    setScanning(true);
    try {
      const res = await startScan(targetList);
      setActiveScanId(res.data.id);
      loadScans();

      // Poll for completion
      pollRef.current = setInterval(async () => {
        try {
          const scanRes = await getScan(res.data.id);
          loadScans();
          if (scanRes.data.status === 'completed' || scanRes.data.status === 'failed') {
            clearInterval(pollRef.current);
            setScanning(false);
            setActiveScanId(null);
          }
        } catch {
          clearInterval(pollRef.current);
          setScanning(false);
        }
      }, 2000);
    } catch (err) {
      toast(err.response?.data?.detail || 'Failed to start scan', 'error');
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-white">Scan Management</h1>

      {/* New Scan */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-3">New Scan</h2>
        <p className="text-sm text-gray-400 mb-3">Enter target hosts (one per line). Format: <code className="text-blue-400">hostname</code> or <code className="text-blue-400">hostname:port</code></p>
        <textarea
          className="w-full bg-gray-900 border border-gray-600 rounded-lg p-3 text-sm text-gray-200 font-mono focus:outline-none focus:border-blue-500 resize-y"
          rows={5}
          placeholder={"google.com\ngithub.com\nexample.com:443"}
          value={targets}
          onChange={e => setTargets(e.target.value)}
          disabled={scanning}
        />
        <button
          onClick={handleScan}
          disabled={scanning || !targets.trim()}
          className="mt-3 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white rounded-lg font-medium text-sm transition-colors"
        >
          {scanning ? (
            <span className="flex items-center gap-2">
              <span className="animate-spin h-4 w-4 border-2 border-white/30 border-t-white rounded-full"></span>
              Scanning...
            </span>
          ) : 'Start Scan'}
        </button>

        {/* CSV Upload */}
        <div className="mt-4 pt-4 border-t border-gray-700">
          <p className="text-sm text-gray-400 mb-2">Or upload a CSV file (columns: host, port)</p>
          <input
            type="file"
            accept=".csv"
            disabled={scanning}
            onChange={async (e) => {
              const file = e.target.files[0];
              if (!file) return;
              setScanning(true);
              try {
                const res = await startScanCSV(file);
                setActiveScanId(res.data.id);
                loadScans();
                pollRef.current = setInterval(async () => {
                  try {
                    const scanRes = await getScan(res.data.id);
                    loadScans();
                    if (scanRes.data.status === 'completed' || scanRes.data.status === 'failed') {
                      clearInterval(pollRef.current);
                      setScanning(false);
                      setActiveScanId(null);
                    }
                  } catch {
                    clearInterval(pollRef.current);
                    setScanning(false);
                  }
                }, 2000);
              } catch {
                setScanning(false);
              }
              e.target.value = '';
            }}
            className="text-sm text-gray-400 file:mr-3 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-gray-700 file:text-gray-300 file:cursor-pointer hover:file:bg-gray-600"
          />
        </div>
      </div>

      {/* Scan Progress */}
      {activeScanId && (
        <div className="bg-blue-900/30 border border-blue-700 rounded-xl p-4">
          <p className="text-blue-300 text-sm font-medium">Scan #{activeScanId} in progress...</p>
          <div className="mt-2 h-2 bg-gray-700 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full transition-all duration-500 animate-pulse" style={{ width: '100%' }}></div>
          </div>
        </div>
      )}

      {/* Scan History */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Scan History</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-gray-400 border-b border-gray-700">
              <tr>
                <th className="py-2 px-3">ID</th>
                <th className="py-2 px-3">Date</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Targets</th>
                <th className="py-2 px-3">Progress</th>
                <th className="py-2 px-3">Report</th>
              </tr>
            </thead>
            <tbody className="text-gray-300">
              {scans.length === 0 && (
                <tr><td colSpan={6} className="text-center py-6 text-gray-500">No scans yet</td></tr>
              )}
              {scans.map(scan => (
                <tr key={scan.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 px-3 font-mono">#{scan.id}</td>
                  <td className="py-2 px-3">{new Date(scan.created_at).toLocaleString()}</td>
                  <td className="py-2 px-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${scan.status === 'completed' ? 'bg-emerald-900 text-emerald-300' : scan.status === 'running' ? 'bg-blue-900 text-blue-300' : scan.status === 'failed' ? 'bg-red-900 text-red-300' : 'bg-gray-700 text-gray-300'}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="py-2 px-3">{scan.total_targets}</td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-gray-700 rounded-full">
                        <div className="h-full bg-blue-500 rounded-full" style={{ width: `${scan.total_targets ? (scan.completed_targets / scan.total_targets * 100) : 0}%` }}></div>
                      </div>
                      <span className="text-xs">{scan.completed_targets}/{scan.total_targets}</span>
                    </div>
                  </td>
                  <td className="py-2 px-3">
                    {scan.status === 'completed' && (
                      <a href={getReportUrl(scan.id)} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 text-xs underline">
                        View Report
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
