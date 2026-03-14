const LABEL_CONFIG = {
  'PQC Ready': { color: 'bg-emerald-500', text: 'text-white', border: 'border-emerald-600' },
  'Quantum-Safe': { color: 'bg-blue-500', text: 'text-white', border: 'border-blue-600' },
  'At Risk': { color: 'bg-amber-500', text: 'text-white', border: 'border-amber-600' },
  'Critical': { color: 'bg-red-600', text: 'text-white', border: 'border-red-700' },
  'Unknown': { color: 'bg-gray-500', text: 'text-white', border: 'border-gray-600' },
};

export default function LabelBadge({ label }) {
  const config = LABEL_CONFIG[label] || LABEL_CONFIG['Unknown'];
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${config.color} ${config.text}`}>
      {label}
    </span>
  );
}
