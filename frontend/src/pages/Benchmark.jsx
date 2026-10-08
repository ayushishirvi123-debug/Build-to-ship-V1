import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Badge, Btn, Card, Stat } from '../ui.jsx';

export default function Benchmark() {
  const [b, setB] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  useEffect(() => { api.get('/api/benchmark/latest').then((r) => setB(r.data)); }, []);
  async function run() {
    setBusy(true); setErr('');
    const r = await api.post('/api/benchmark');
    if (r.status === 200) setB(r.data); else setErr(r.data?.error || 'Benchmark failed. Wait a minute and retry.');
    setBusy(false);
  }
  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Red-team benchmark</h1>
          <p className="max-w-2xl text-sm text-mute">A built-in suite of attacks, normal prompts and personal-data prompts, run against your current policy. It is small and hand-written, so treat the numbers as a regression check rather than a certification.</p>
        </div>
        <Btn onClick={run} disabled={busy}>{busy ? 'Running…' : 'Run benchmark'}</Btn>
      </header>
      {err && <p role="alert" className="text-sm text-block">{err}</p>}
      {!b ? <Card><p className="py-10 text-center text-sm text-mute">No run yet. Press "Run benchmark".</p></Card> : (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Stat label="Attacks blocked" value={`${b.detectionRate}%`} tone="text-ok" hint={`${b.counts.attacks} attack prompts`} />
            <Stat label="False positives" value={`${b.falsePositiveRate}%`} tone={b.falsePositiveRate > 0 ? 'text-block' : 'text-ok'} hint={`${b.counts.benign} normal prompts`} />
            <Stat label="PII redacted" value={`${b.piiRedactionRate}%`} tone="text-ok" hint={`${b.counts.pii} prompts with PII`} />
            <Stat label="Guardrail p50 / p95" value={`${b.latency.p50} / ${b.latency.p95} ms`} hint={b.aiEnabled ? `Gemini path avg ${b.latency.aiPathAvg} ms (${b.latency.aiCalls} calls)` : 'regex-only run, no Gemini calls'} />
          </div>
          {!b.aiEnabled && <p className="rounded-lg bg-redact/10 px-3 py-2 text-sm text-redact">This run used regex only. Semantic attacks such as roleplay jailbreaks need the Gemini inspector, so detection is lower than it will be with a key configured.</p>}
          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Result by attack type">
              <ul className="space-y-2">{b.kinds.map((k) => (
                <li key={k.kind}>
                  <div className="flex justify-between text-sm"><span>{k.kind}</span><span className="font-mono text-xs">{k.passed}/{k.total}</span></div>
                  <div className="h-1.5 rounded bg-paper"><div className={`h-1.5 rounded ${k.passed === k.total ? 'bg-ok' : 'bg-block'}`} style={{ width: `${(k.passed / k.total) * 100}%` }} /></div>
                </li>))}</ul>
            </Card>
            <Card title="Missed cases">
              {b.results.filter((r) => !r.pass).length === 0 ? <p className="text-sm text-ok">Every case behaved as expected.</p> : (
                <ul className="space-y-2">{b.results.filter((r) => !r.pass).map((r, i) => (
                  <li key={i} className="rounded-lg bg-paper p-2 text-sm"><div className="flex items-center gap-2"><Badge action={r.action} /><span className="text-xs text-mute">expected {r.expect}, risk {r.risk}</span></div><p className="mt-1 break-words font-mono text-xs">{r.prompt}</p></li>))}</ul>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
