import React, { createContext, useContext, useState } from 'react';
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import Login from './pages/Login.jsx';
import Sandbox from './pages/Sandbox.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Logs from './pages/Logs.jsx';
import Policy from './pages/Policy.jsx';
import Benchmark from './pages/Benchmark.jsx';
import Integrate from './pages/Integrate.jsx';

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

const NAV = [
  ['/', 'Sandbox'],
  ['/dashboard', 'Dashboard'],
  ['/logs', 'Audit log'],
  ['/policy', 'Policy'],
  ['/benchmark', 'Benchmark'],
  ['/integrate', 'Integrate'],
];

function Shell({ children }) {
  const { email, logout } = useAuth();
  return (
    <div className="min-h-screen md:flex">
      <aside className="shrink-0 bg-ink text-white md:sticky md:top-0 md:h-screen md:w-56">
        <div className="flex items-center justify-between px-4 py-3 md:block md:py-5">
          <div>
            <div className="text-lg font-bold tracking-tight">PromptShield</div>
            <div className="hidden text-xs text-white/60 md:block">AI guardrail firewall</div>
          </div>
          <button onClick={logout} className="text-xs text-white/70 hover:text-white md:hidden">Sign out</button>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:pb-0">
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to} end={to === '/'}
              className={({ isActive }) => `whitespace-nowrap rounded-lg px-3 py-2 text-sm ${isActive ? 'bg-white text-ink font-semibold' : 'text-white/75 hover:bg-white/10'}`}>
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto hidden px-4 py-4 text-xs text-white/60 md:absolute md:bottom-0 md:block md:w-56">
          <div className="truncate">{email}</div>
          <button onClick={logout} className="mt-1 text-white/80 underline hover:text-white">Sign out</button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-8"><div className="mx-auto max-w-6xl">{children}</div></main>
    </div>
  );
}

export default function App() {
  const nav = useNavigate();
  const [token, setToken] = useState(localStorage.getItem('ps_token'));
  const [email, setEmail] = useState(localStorage.getItem('ps_email') || '');
  const value = {
    token, email,
    login: (t, e) => { localStorage.setItem('ps_token', t); localStorage.setItem('ps_email', e); setToken(t); setEmail(e); },
    logout: () => { localStorage.removeItem('ps_token'); setToken(null); nav('/login'); },
  };
  return (
    <AuthCtx.Provider value={value}>
      <Routes>
        <Route path="/login" element={token ? <Navigate to="/" /> : <Login />} />
        <Route path="/*" element={token ? (
          <Shell>
            <Routes>
              <Route index element={<Sandbox />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="logs" element={<Logs />} />
              <Route path="policy" element={<Policy />} />
              <Route path="benchmark" element={<Benchmark />} />
              <Route path="integrate" element={<Integrate />} />
              <Route path="*" element={<Navigate to="/" />} />
            </Routes>
          </Shell>
        ) : <Navigate to="/login" />} />
      </Routes>
    </AuthCtx.Provider>
  );
}
