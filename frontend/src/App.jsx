import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import { LayoutDashboard, Server, Scan, FileJson, ShieldAlert, Shield, Clock, Scale, Award } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Assets from './pages/Assets';
import ScansPage from './pages/Scans';
import CBOM from './pages/CBOM';
import Recommendations from './pages/Recommendations';
import HNDLRisk from './pages/HNDLRisk';
import Compliance from './pages/Compliance';
import { ToastProvider } from './components/Toast';
import './App.css';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/assets', label: 'Assets', icon: Server },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/cbom', label: 'CBOM', icon: FileJson },
  { to: '/recommendations', label: 'Recommendations', icon: ShieldAlert },
  { to: '/hndl', label: 'HNDL Risk', icon: Clock },
  { to: '/compliance', label: 'Compliance', icon: Scale },
];

function App() {
  return (
    <BrowserRouter>
    <ToastProvider>
      <div className="flex min-h-screen bg-slate-950">
        {/* Sidebar */}
        <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
          {/* Brand */}
          <div className="p-5 border-b border-slate-800">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-400" />
              <div>
                <h1 className="text-lg font-bold text-white leading-tight">PNB QuantumShield</h1>
                <p className="text-[10px] text-slate-500 uppercase tracking-widest">Crypto Scanner</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-3 space-y-1">
            {navItems.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800'
                  }`
                }
              >
                <Icon className="w-4 h-4" />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t border-slate-800">
            <p className="text-[10px] text-slate-600 text-center">Punjab National Bank</p>
            <p className="text-[10px] text-slate-600 text-center">Cybersecurity Hackathon 2025-26</p>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6 overflow-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/cbom" element={<CBOM />} />
            <Route path="/recommendations" element={<Recommendations />} />
            <Route path="/hndl" element={<HNDLRisk />} />
            <Route path="/compliance" element={<Compliance />} />
          </Routes>
        </main>
      </div>
    </ToastProvider>
    </BrowserRouter>
  );
}

export default App;
