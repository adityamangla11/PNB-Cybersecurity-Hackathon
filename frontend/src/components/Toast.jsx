import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import { X, AlertCircle, CheckCircle, Info } from 'lucide-react';

const ToastContext = createContext(null);

const ICONS = {
  error: AlertCircle,
  success: CheckCircle,
  info: Info,
};

const STYLES = {
  error: 'bg-red-900/90 border-red-700 text-red-200',
  success: 'bg-emerald-900/90 border-emerald-700 text-emerald-200',
  info: 'bg-blue-900/90 border-blue-700 text-blue-200',
};

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((message, type = 'error', duration = 5000) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    if (duration > 0) {
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
    }
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      {/* Toast Container */}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
        {toasts.map(toast => {
          const Icon = ICONS[toast.type] || Info;
          return (
            <div key={toast.id} className={`flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg backdrop-blur-sm animate-slide-in ${STYLES[toast.type]}`}>
              <Icon className="w-5 h-5 mt-0.5 shrink-0" />
              <p className="text-sm flex-1">{toast.message}</p>
              <button onClick={() => removeToast(toast.id)} className="shrink-0 opacity-60 hover:opacity-100">
                <X className="w-4 h-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const addToast = useContext(ToastContext);
  if (!addToast) throw new Error('useToast must be used within a ToastProvider');
  return addToast;
}
