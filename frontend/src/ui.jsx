import React from 'react';

export const ACTION = {
  ALLOWED: 'bg-ok/10 text-ok ring-ok/30',
  REDACTED: 'bg-redact/10 text-redact ring-redact/30',
  BLOCKED: 'bg-block/10 text-block ring-block/30',
  UNGUARDED: 'bg-slate-200 text-slate-700 ring-slate-300',
};
export const Badge = ({ action }) => (
  <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${ACTION[action] || ACTION.UNGUARDED}`}>
    {action === 'UNGUARDED' ? 'No protection' : action[0] + action.slice(1).toLowerCase()}
  </span>
);

export const Card = ({ title, right, children, className = '' }) => (
  <section className={`min-w-0 rounded-xl border border-line bg-white p-4 ${className}`}>
    {(title || right) && (
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {right}
      </div>
    )}
    {children}
  </section>
);

export const Stat = ({ label, value, tone = 'text-ink', hint }) => (
  <div className="rounded-xl border border-line bg-white p-4">
    <div className="text-sm text-mute">{label}</div>
    <div className={`mt-1 text-3xl font-semibold tabular-nums ${tone}`}>{value ?? '–'}</div>
    {hint && <div className="mt-1 text-xs text-mute">{hint}</div>}
  </div>
);

export const Btn = ({ kind = 'solid', className = '', ...p }) => (
  <button
    {...p}
    className={`rounded-lg px-4 py-2 text-sm font-semibold transition-colors disabled:opacity-50 ${
      kind === 'solid' ? 'bg-ink text-white hover:bg-accent' : 'border border-line bg-white text-ink hover:border-ink'
    } ${className}`}
  />
);

export function Toggle({ checked, onChange, label, hint }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4 py-3">
      <span>
        <span className="block text-sm font-medium">{label}</span>
        {hint && <span className="block text-xs text-mute">{hint}</span>}
      </span>
      <input type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-1 h-5 w-9 shrink-0 cursor-pointer accent-accent" />
    </label>
  );
}

/* original prompt with detected PII spans highlighted */
export function Original({ text, spans = [] }) {
  const parts = [];
  let last = 0;
  [...spans].filter((s) => s.start != null).sort((a, b) => a.start - b.start).forEach((s, i) => {
    parts.push(text.slice(last, s.start));
    parts.push(<mark key={i} className="rounded bg-redact/20 px-0.5 text-ink">{text.slice(s.start, s.end)}</mark>);
    last = s.end;
  });
  parts.push(text.slice(last));
  return <p className="whitespace-pre-wrap break-words font-mono text-[13px] leading-6">{parts}</p>;
}

/* text with [EMAIL_1]-style tokens highlighted */
export function Tokens({ text }) {
  const bits = text.split(/(\[[A-Z_]+_\d+\]|\[REDACTED_[A-Z_]+\])/g);
  return (
    <p className="whitespace-pre-wrap break-words font-mono text-[13px] leading-6">
      {bits.map((b, i) => (/^\[[A-Z_]+(_\d+)?\]$|^\[REDACTED/.test(b) ? <mark key={i} className="rounded bg-ok/15 px-0.5 text-ok">{b}</mark> : b))}
    </p>
  );
}

const DOT = { pass: 'bg-ok', redact: 'bg-redact', flag: 'bg-block', error: 'bg-block', warn: 'bg-block', skipped: 'bg-slate-300' };
/* the pipeline lane: every layer a request passes through, with its own latency */
export function Stages({ stages = [], latency }) {
  const max = Math.max(1, ...stages.map((s) => s.ms));
  return (
    <div>
      <ol className="relative ml-1.5 border-l border-line">
        {stages.map((s, i) => (
          <li key={i} className="relative py-1.5 pl-5">
            <span className={`absolute -left-[5px] top-3 h-2.5 w-2.5 rounded-full ${DOT[s.status] || 'bg-slate-300'}`} />
            <div className="flex items-baseline justify-between gap-3">
              <span className={`text-sm ${s.status === 'skipped' ? 'text-mute' : 'font-medium'}`}>{s.name}</span>
              <span className="font-mono text-xs tabular-nums text-mute">{s.status === 'skipped' ? 'skipped' : `${s.ms} ms`}</span>
            </div>
            <div className="text-xs text-mute">{s.detail}</div>
            {s.status !== 'skipped' && <div className="mt-1 h-1 rounded bg-paper"><div className={`h-1 rounded ${DOT[s.status]}`} style={{ width: `${Math.max(2, (s.ms / max) * 100)}%` }} /></div>}
          </li>
        ))}
      </ol>
      {latency && (
        <p className="mt-2 text-xs text-mute">
          Guardrail overhead <b className="text-ink">{latency.guard} ms</b> (regex {latency.regex} ms{latency.ai ? `, Gemini ${latency.ai} ms` : ''}) · model {latency.llm} ms
        </p>
      )}
    </div>
  );
}

export const catLabel = (c) => (c || '').replace(/_/g, ' ').toLowerCase().replace(/^./, (x) => x.toUpperCase());
export const CAT_COLOR = { PROMPT_INJECTION: '#c92a4b', JAILBREAK: '#e8590c', DATA_EXFILTRATION: '#862e9c', TOXICITY: '#7048e8', INSPECTOR_TAMPERING: '#0b7285', OUTPUT_LEAK: '#a61e4d', INSPECTOR_ERROR: '#868e96', PII_LEAKAGE: '#b86e00' };
