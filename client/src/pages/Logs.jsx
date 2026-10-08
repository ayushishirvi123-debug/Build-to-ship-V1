import React, { useCallback, useEffect, useState } from 'react';
import { api, download } from '../api.js';
import { Badge, Btn, Card, Stages, Tokens, catLabel } from '../ui.jsx';

const FILTERS = ['ALL', 'BLOCKED', 'REDACTED', 'ALLOWED', 'UNGUARDED'];

export default function Logs() {
  const [filter, setFilter] = useState('ALL');
  const [data, setData] = useState({ total: 0, events: [] });
  const [open, setOpen] = useState(null);
  const [page, setPage] = useState(0);
  const per = 15;

  const load = useCallback(() => {
    api.get('/api/v1/events', { params: { limit: per, offset: page * per, action: filter === 'ALL' ? undefined : filter } }).then((r) => setData(r.data));
  }, [filter, page]);
  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, [load]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Audit log</h1>
          <p className="text-sm text-mute">Every decision, explained. Raw prompts are never stored, only the version with personal data tokenized.</p>
        </div>
        <div className="flex gap-2">
          <Btn kind="ghost" onClick={() => download('/api/v1/events/export?format=csv', 'promptshield-audit.csv')}>Export CSV</Btn>
          <Btn kind="ghost" onClick={() => download('/api/v1/events/export?format=json', 'promptshield-audit.json')}>Export JSON</Btn>
        </div>
      </header>
      <div className="flex flex-wrap gap-2">
        {FILTERS.map((f) => (
          <button key={f} onClick={() => { setFilter(f); setPage(0); }} className={`rounded-full border px-3 py-1 text-xs ${filter === f ? 'border-ink bg-ink text-white' : 'border-line bg-white'}`}>
            {f === 'ALL' ? 'All' : f === 'UNGUARDED' ? 'No protection' : f[0] + f.slice(1).toLowerCase()}
          </button>
        ))}
      </div>
      <Card className="overflow-x-auto p-0">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line text-xs text-mute"><tr><th className="p-3">Time (UTC)</th><th className="p-3">Decision</th><th className="p-3">Category</th><th className="p-3">Risk</th><th className="p-3">Prompt as stored</th></tr></thead>
          <tbody>
            {data.events.map((e) => (
              <tr key={e.id} onClick={() => setOpen(e)} className="cursor-pointer border-b border-line/60 hover:bg-paper">
                <td className="whitespace-nowrap p-3 font-mono text-xs">{e.created_at}{e.seeded && <span className="ml-1.5 rounded bg-paper px-1 text-[10px] text-mute">sample</span>}</td>
                <td className="p-3"><Badge action={e.action} /></td>
                <td className="whitespace-nowrap p-3">{catLabel(e.category)}</td>
                <td className="p-3 font-mono tabular-nums">{e.risk}</td>
                <td className="max-w-xs truncate p-3 text-mute">{e.sanitized}</td>
              </tr>
            ))}
            {data.events.length === 0 && <tr><td colSpan={5} className="p-8 text-center text-mute">No events for this filter.</td></tr>}
          </tbody>
        </table>
      </Card>
      <div className="flex items-center justify-between text-sm text-mute">
        <span>{data.total} events</span>
        <div className="flex gap-2">
          <Btn kind="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Btn>
          <Btn kind="ghost" disabled={(page + 1) * per >= data.total} onClick={() => setPage(page + 1)}>Next</Btn>
        </div>
      </div>

      {open && (
        <div className="fixed inset-0 z-20 flex justify-end bg-ink/40" onClick={() => setOpen(null)}>
          <aside role="dialog" aria-label="Decision details" className="h-full w-full max-w-md overflow-y-auto bg-white p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold">Why this decision?</h2><button onClick={() => setOpen(null)} className="text-sm text-mute underline">Close</button></div>
            <div className="mb-3 flex items-center gap-2"><Badge action={open.action} /><span className="text-sm">{catLabel(open.category)} · risk {open.risk} · decided by {open.source || 'n/a'}</span></div>
            <p className="mb-4 text-sm">{open.reason}</p>
            {open.rules.length > 0 && (<><div className="mb-1 text-xs font-semibold text-mute">Rules that matched</div>
              <ul className="mb-4 space-y-2">{open.rules.map((r) => <li key={r.id} className="rounded-lg bg-paper p-2 text-sm"><b>{r.label}</b> <span className="font-mono text-xs text-mute">weight {r.w}</span><div className="text-xs text-mute">{r.explain}</div></li>)}</ul></>)}
            {open.pii.length > 0 && <p className="mb-4 text-sm"><b>Personal data types masked:</b> {open.pii.join(', ')}</p>}
            <div className="mb-1 text-xs font-semibold text-mute">Prompt as stored (personal data tokenized)</div>
            <div className="mb-4 rounded-lg bg-paper p-3"><Tokens text={open.sanitized || ''} /></div>
            <div className="mb-1 text-xs font-semibold text-mute">Latency</div>
            <p className="font-mono text-xs">guard {open.latency.guard ?? 0} ms · regex {open.latency.regex ?? 0} ms · gemini {open.latency.ai ?? 0} ms · model {open.latency.llm ?? 0} ms</p>
          </aside>
        </div>
      )}
    </div>
  );
}
