import { Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';

export default function ScoreCard({ title, value, icon, color = 'blue' }) {
  const colorClasses = {
    blue: 'from-blue-600 to-blue-800 border-blue-500',
    green: 'from-emerald-600 to-emerald-800 border-emerald-500',
    yellow: 'from-amber-500 to-amber-700 border-amber-400',
    red: 'from-red-600 to-red-800 border-red-500',
    purple: 'from-purple-600 to-purple-800 border-purple-500',
  };

  const icons = {
    shield: Shield,
    'shield-check': ShieldCheck,
    'shield-alert': ShieldAlert,
    'shield-x': ShieldX,
  };

  const IconComponent = icons[icon] || Shield;

  return (
    <div className={`bg-gradient-to-br ${colorClasses[color] || colorClasses.blue} border rounded-xl p-5 shadow-lg`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-white/70 font-medium">{title}</p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
        </div>
        <IconComponent className="w-10 h-10 text-white/40" />
      </div>
    </div>
  );
}
