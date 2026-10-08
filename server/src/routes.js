import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { auth, validate } from './auth.js';
import { db, getPolicy, setPolicy, saveEvent, parseEvent, DEFAULT_POLICY } from './db.js';
import { runPipeline } from './pipeline/index.js';
import { runBenchmark } from './benchmark.js';
import { config } from './config.js';

const r = Router();
const limiter = rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false });

r.get('/health', (_q, s) => s.json({ ok: true, ai: config.geminiKey ? `gemini:${config.geminiModel}` : 'regex-only (no GEMINI_API_KEY)' }));

/* ---- guarded chat ---- */
const chatSchema = z.object({ prompt: z.string().min(1).max(8000), guardrails: z.boolean().default(true) });
const publicOut = (o, eventId) => ({
  eventId, action: o.action, category: o.category, risk: o.risk, source: o.source, reason: o.reason,
  rules: o.rules.map(({ id, label, explain, w }) => ({ id, label, explain, w })),
  spans: o.spans, llmInput: o.llmInput, response: o.response, llmMode: o.llmMode, leaked: o.leaked,
  stages: o.stages, latency: o.latency,
});

r.post('/api/v1/chat', auth, limiter, validate(chatSchema), async (req, res) => {
  const out = await runPipeline({ prompt: req.body.prompt, policy: getPolicy(req.user.id), guardrails: req.body.guardrails });
  const id = saveEvent(req.user.id, out);
  res.status(out.action === 'BLOCKED' ? 403 : 200).json(publicOut(out, id));
});

/* ---- OpenAI-compatible drop-in proxy: change one base URL ---- */
const oaiSchema = z.object({
  model: z.string().optional(),
  messages: z.array(z.object({ role: z.string(), content: z.union([z.string(), z.array(z.any())]) })).min(1),
});
r.post('/v1/chat/completions', auth, limiter, validate(oaiSchema), async (req, res) => {
  const text = (c) => (typeof c === 'string' ? c : c.map((p) => p.text || '').join(' '));
  const lastUser = [...req.body.messages].reverse().find((m) => m.role === 'user');
  if (!lastUser) return res.status(400).json({ error: { message: 'No user message', type: 'invalid_request_error' } });
  const out = await runPipeline({ prompt: text(lastUser.content), policy: getPolicy(req.user.id), guardrails: true });
  const id = saveEvent(req.user.id, out);
  res.set('x-promptshield-event', String(id));
  if (out.action === 'BLOCKED') {
    return res.status(403).json({ error: { message: out.response, type: 'guardrail_blocked', code: out.category, risk_score: out.risk, event_id: id } });
  }
  res.json({
    id: `chatcmpl-ps-${id}`, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model: req.body.model || 'promptshield-proxy',
    choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: out.response } }],
    promptshield: { action: out.action, risk_score: out.risk, category: out.category, guard_ms: out.latency.guard },
  });
});

/* ---- audit log ---- */
r.get('/api/v1/events', auth, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 25, 100), offset = Number(req.query.offset) || 0;
  const action = ['ALLOWED', 'REDACTED', 'BLOCKED', 'UNGUARDED'].includes(req.query.action) ? req.query.action : null;
  const where = 'user_id=?' + (action ? ' AND action=?' : '');
  const args = action ? [req.user.id, action] : [req.user.id];
  const rows = db.prepare(`SELECT * FROM events WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset);
  const total = db.prepare(`SELECT COUNT(*) c FROM events WHERE ${where}`).get(...args).c;
  res.json({ total, events: rows.map(parseEvent) });
});

r.get('/api/v1/events/export', auth, (req, res) => {
  const rows = db.prepare('SELECT * FROM events WHERE user_id=? ORDER BY id DESC').all(req.user.id).map(parseEvent);
  if (req.query.format === 'csv') {
    const cols = ['id', 'created_at', 'action', 'category', 'risk', 'source', 'reason', 'pii', 'sanitized'];
    const esc = (v) => `"${String(Array.isArray(v) ? v.join('|') : v ?? '').replace(/"/g, '""')}"`;
    res.set({ 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="promptshield-audit.csv"' });
    return res.send([cols.join(','), ...rows.map((e) => cols.map((c) => esc(e[c])).join(','))].join('\n'));
  }
  res.set('content-disposition', 'attachment; filename="promptshield-audit.json"').json(rows);
});

r.get('/api/v1/events/:id', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM events WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'Event not found' });
  res.json(parseEvent(row));
});

/* ---- analytics ---- */
r.get('/api/v1/stats', auth, (req, res) => {
  const uid = req.user.id;
  const one = (sql, ...a) => db.prepare(sql).all(uid, ...a);
  const byAction = Object.fromEntries(one('SELECT action,COUNT(*) c FROM events WHERE user_id=? AND guardrails=1 GROUP BY action').map((x) => [x.action, x.c]));
  const byCategory = one("SELECT category name,COUNT(*) value FROM events WHERE user_id=? AND guardrails=1 AND category NOT IN ('SAFE','NONE') GROUP BY category ORDER BY value DESC");
  const dayRows = one("SELECT date(created_at) d,action,COUNT(*) c FROM events WHERE user_id=? AND guardrails=1 AND created_at>=datetime('now','-6 days') GROUP BY d,action");
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    const row = { day: d.slice(5), ALLOWED: 0, REDACTED: 0, BLOCKED: 0 };
    dayRows.filter((x) => x.d === d).forEach((x) => (row[x.action] = x.c));
    days.push(row);
  }
  const recent = one('SELECT latency,pii,source FROM events WHERE user_id=? AND guardrails=1 ORDER BY id DESC LIMIT 300').map((x) => ({ l: JSON.parse(x.latency || '{}'), pii: JSON.parse(x.pii || '[]') }));
  const avg = (f) => { const v = recent.map((x) => x.l[f]).filter((n) => n > 0); return v.length ? +(v.reduce((a, b) => a + b, 0) / v.length).toFixed(1) : null; };
  const piiCount = {};
  recent.forEach((x) => x.pii.forEach((t) => (piiCount[t] = (piiCount[t] || 0) + 1)));
  const total = Object.values(byAction).reduce((a, b) => a + b, 0);
  res.json({
    total, allowed: byAction.ALLOWED || 0, redacted: byAction.REDACTED || 0, blocked: byAction.BLOCKED || 0,
    unguarded: one('SELECT COUNT(*) c FROM events WHERE user_id=? AND guardrails=0')[0].c,
    blockRate: total ? +(((byAction.BLOCKED || 0) / total) * 100).toFixed(1) : 0,
    byCategory, days, avgGuardMs: avg('guard'), avgAiMs: avg('ai'),
    pii: Object.entries(piiCount).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value),
  });
});

/* ---- policy ---- */
const policySchema = z.object({
  piiMasking: z.boolean(), reversibleRedaction: z.boolean(), injectionDetection: z.boolean(), toxicityDetection: z.boolean(), outputGuard: z.boolean(),
  strictness: z.enum(['low', 'medium', 'high']), aiMode: z.enum(['off', 'tiered', 'always']), failMode: z.enum(['closed', 'open']),
});
r.get('/api/v1/policy', auth, (req, res) => res.json({ policy: getPolicy(req.user.id), defaults: DEFAULT_POLICY, aiConfigured: !!config.geminiKey }));
r.put('/api/v1/policy', auth, validate(policySchema), (req, res) => { setPolicy(req.user.id, req.body); res.json({ policy: req.body }); });

/* ---- benchmark ---- */
r.post('/api/v1/benchmark', auth, rateLimit({ windowMs: 60_000, limit: 6 }), async (req, res) => {
  const result = await runBenchmark(getPolicy(req.user.id));
  db.prepare('INSERT INTO benchmarks(user_id,json) VALUES(?,?)').run(req.user.id, JSON.stringify(result));
  res.json({ ...result, createdAt: new Date().toISOString() });
});
r.get('/api/v1/benchmark/latest', auth, (req, res) => {
  const row = db.prepare('SELECT * FROM benchmarks WHERE user_id=? ORDER BY id DESC LIMIT 1').get(req.user.id);
  res.json(row ? { ...JSON.parse(row.json), createdAt: row.created_at } : null);
});

export default r;
