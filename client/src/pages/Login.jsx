import React, { useState } from 'react';
import { api } from '../api.js';
import { useAuth } from '../App.jsx';
import { Btn } from '../ui.jsx';

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e, creds) {
    e?.preventDefault();
    const body = creds || { email, password };
    setBusy(true); setErr('');
    try {
      const r = await api.post(`/api/auth/${creds ? 'login' : mode}`, body);
      if (r.status >= 400) setErr(r.data?.details?.join(', ') || r.data?.error || 'Something went wrong');
      else login(r.data.token, body.email);
    } catch { setErr('Cannot reach the server. Check that the backend is running.'); }
    setBusy(false);
  }

  return (
    <div className="grid min-h-screen md:grid-cols-2">
      <div className="flex flex-col justify-between bg-ink p-8 text-white md:p-12">
        <div className="text-lg font-bold">PromptShield</div>
        <div className="py-10">
          <h1 className="max-w-md text-3xl font-bold leading-tight md:text-4xl">Your LLM should never see the customer's SSN, or obey a stranger's instructions.</h1>
          <p className="mt-4 max-w-md text-white/70">A firewall between your users and your model: it redacts personal data, blocks prompt injection, checks the model's reply, and keeps an audit trail that contains no raw prompts.</p>
        </div>
        <p className="text-xs text-white/50">Regex layer in milliseconds, Gemini inspector only when a prompt is ambiguous.</p>
      </div>
      <div className="flex items-center justify-center p-6">
        <form onSubmit={submit} className="w-full max-w-sm space-y-4">
          <h2 className="text-2xl font-semibold">{mode === 'login' ? 'Sign in' : 'Create your account'}</h2>
          <label className="block text-sm font-medium">Email
            <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1 w-full rounded-lg border border-line bg-white px-3 py-2" />
          </label>
          <label className="block text-sm font-medium">Password
            <input type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} className="mt-1 w-full rounded-lg border border-line bg-white px-3 py-2" />
            {mode === 'register' && <span className="text-xs text-mute">At least 8 characters.</span>}
          </label>
          {err && <p role="alert" className="text-sm text-block">{err}</p>}
          <Btn type="submit" disabled={busy} className="w-full">{mode === 'login' ? 'Sign in' : 'Create account'}</Btn>
          <Btn type="button" kind="ghost" disabled={busy} className="w-full" onClick={(e) => submit(e, { email: 'demo@promptshield.dev', password: 'Demo@1234' })}>Use the demo account</Btn>
          <button type="button" className="text-sm text-accent underline" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
            {mode === 'login' ? 'Need an account? Register' : 'Have an account? Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
