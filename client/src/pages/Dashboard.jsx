import React, { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { api } from '../api.js';
import { CAT_COLOR, Card, Stat, catLabel } from '../ui.jsx';

export default function Dashboard() {
  const [s, setS] = useState(null);
  useEffect(() => {
    let alive = true;
    const load = () => api.get('/api/v1/stats').then((r) => alive && setS(r.data));
    load();
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  if (!s) return <p className="text-mute">Loading…</p>;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-2xl font-bold">Security dashboard</h1>
        <p className="text-sm text-mute">Updates every 5 seconds. Includes seeded sample history for the demo account.</p>
      </header>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Requests screened" value={s.total} />
        <Stat label="Blocked" value={s.blocked} tone="text-block" hint={`${s.blockRate}% of traffic`} />
        <Stat label="PII redacted" value={s.redacted} tone="text-redact" />
        <Stat label="Passed clean" value={s.allowed} tone="text-ok" />
        <Stat label="Avg guardrail time" value={s.avgGuardMs != null ? `${s.avgGuardMs} ms` : null} hint={s.avgAiMs ? `Gemini path ${s.avgAiMs} ms` : 'regex path'} />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Decisions per day">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={s.days}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d9dfea" vertical={false} />
                <XAxis dataKey="day" tick={{ fontSize: 12 }} /><YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
                <Tooltip /><Legend />
                <Bar dataKey="BLOCKED" name="Blocked" stackId="a" fill="#c92a4b" />
                <Bar dataKey="REDACTED" name="Redacted" stackId="a" fill="#b86e00" />
                <Bar dataKey="ALLOWED" name="Allowed" stackId="a" fill="#0f9d74" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Threat breakdown">
          {s.byCategory.length === 0 ? <p className="py-16 text-center text-sm text-mute">No threats yet. Try the sandbox.</p> : (
            <div className="h-64">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={s.byCategory.map((c) => ({ ...c, label: catLabel(c.name) }))} dataKey="value" nameKey="label" innerRadius={55} outerRadius={90} paddingAngle={2}>
                    {s.byCategory.map((c) => <Cell key={c.name} fill={CAT_COLOR[c.name] || '#868e96'} />)}
                  </Pie>
                  <Tooltip /><Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>
      <Card title="Sensitive data masked, by type">
        {s.pii.length === 0 ? <p className="text-sm text-mute">No personal data detected yet.</p> : (
          <div className="h-48">
            <ResponsiveContainer>
              <BarChart data={s.pii} layout="vertical" margin={{ left: 30 }}>
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} /><YAxis type="category" dataKey="name" tick={{ fontSize: 12 }} width={100} />
                <Tooltip /><Bar dataKey="value" name="Items" fill="#2f4bdb" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>
    </div>
  );
}
