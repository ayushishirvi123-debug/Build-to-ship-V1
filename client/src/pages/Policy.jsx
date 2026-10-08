import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Btn, Card, Toggle } from '../ui.jsx';

const Select = ({ label, hint, value, onChange, options }) => (
  <label className="flex items-start justify-between gap-4 py-3">
    <span><span className="block text-sm font-medium">{label}</span><span className="block text-xs text-mute">{hint}</span></span>
    <select value={value} onChange={(e) => onChange(e.target.value)} className="rounded-lg border border-line bg-white px-2 py-1 text-sm">
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  </label>
);

export default function Policy() {
  const [p, setP] = useState(null);
  const [ai, setAi] = useState(false);
  const [msg, setMsg] = useState('');
  useEffect(() => { api.get('/api/v1/policy').then((r) => { setP(r.data.policy); setAi(r.data.aiConfigured); }); }, []);
  if (!p) return <p className="text-mute">Loading…</p>;
  const set = (k) => (v) => { setP({ ...p, [k]: v }); setMsg(''); };
  const save = async () => { const r = await api.put('/api/v1/policy', p); setMsg(r.status === 200 ? 'Policy saved. It applies to your next request.' : 'Could not save policy.'); };

  return (
    <div className="max-w-2xl space-y-5">
      <header><h1 className="text-2xl font-bold">Policy</h1><p className="text-sm text-mute">Control what the firewall checks and how strict it is.</p></header>
      <Card title="Detection">
        <div className="divide-y divide-line">
          <Toggle label="Prompt injection and jailbreak detection" hint="Instruction overrides, persona jailbreaks, fake delimiters, attacks on the firewall." checked={p.injectionDetection} onChange={set('injectionDetection')} />
          <Toggle label="Toxicity and harmful requests" hint="Threats, abuse, weapons and malware requests." checked={p.toxicityDetection} onChange={set('toxicityDetection')} />
          <Toggle label="Mask personal data" hint="Emails, phone numbers, SSN, cards, Aadhaar, PAN and API keys become tokens before reaching the model." checked={p.piiMasking} onChange={set('piiMasking')} />
          <Toggle label="Restore masked values in the reply" hint="The user sees their own data again; the model never does." checked={p.reversibleRedaction} onChange={set('reversibleRedaction')} />
          <Toggle label="Check the model's response" hint="Withhold replies that leak the system prompt or contain raw personal data." checked={p.outputGuard} onChange={set('outputGuard')} />
        </div>
      </Card>
      <Card title="Behaviour">
        <div className="divide-y divide-line">
          <Select label="Strictness" hint="Higher blocks on weaker signals, with more false positives." value={p.strictness} onChange={set('strictness')} options={[['low', 'Low (block at 80)'], ['medium', 'Medium (block at 60)'], ['high', 'High (block at 40)']]} />
          <Select label="Gemini inspector" hint={ai ? 'Tiered calls Gemini only for ambiguous prompts, keeping most requests in milliseconds.' : 'No GEMINI_API_KEY on the server: the inspector is unavailable and regex-only mode is used.'} value={p.aiMode} onChange={set('aiMode')} options={[['off', 'Off (regex only)'], ['tiered', 'Tiered (ambiguous only)'], ['always', 'Always']]} />
          <Select label="If the inspector fails" hint="Fail-closed blocks the request when it needed the AI check and could not get it." value={p.failMode} onChange={set('failMode')} options={[['closed', 'Fail closed (block)'], ['open', 'Fail open (allow)']]} />
        </div>
      </Card>
      <div className="flex items-center gap-3"><Btn onClick={save}>Save policy</Btn>{msg && <span role="status" className="text-sm text-ok">{msg}</span>}</div>
    </div>
  );
}
