import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 120000,
});

export const startScan = (targets) => api.post('/scan', { targets });
export const startScanCSV = (file) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/scan/csv', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
};
export const getScan = (scanId) => api.get(`/scan/${scanId}`);
export const listScans = () => api.get('/scans');
export const listAssets = (scanId) => api.get('/assets', { params: scanId ? { scan_id: scanId } : {} });
export const getAsset = (assetId) => api.get(`/asset/${assetId}`);
export const getCBOM = (scanId) => api.get(`/cbom/${scanId}`);
export const getDashboardSummary = () => api.get('/dashboard/summary');
export const getRecommendations = () => api.get('/recommendations');
export const getHNDLRisk = (assetId) => api.get(`/asset/${assetId}/hndl`);
export const getHNDLSummary = () => api.get('/hndl/summary');
export const getCompliance = (assetId) => api.get(`/asset/${assetId}/compliance`);
export const getComplianceSummary = () => api.get('/compliance/summary');
export const getBadgeUrl = (assetId) => `http://localhost:8000/api/asset/${assetId}/badge`;
export const getReportUrl = (scanId) => `http://localhost:8000/api/scan/${scanId}/report`;

export default api;
