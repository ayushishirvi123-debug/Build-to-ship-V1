import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
export const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  api_key_hash TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS policies(user_id INTEGER PRIMARY KEY, json TEXT NOT NULL);
-- Privacy by design: raw prompts and model responses are NEVER stored, only the PII-tokenized prompt.
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  guardrails INTEGER NOT NULL DEFAULT 1,
  action TEXT NOT NULL,
  category TEXT NOT NULL,
  risk INTEGER NOT NULL DEFAULT 0,
  source TEXT,
  reason TEXT,
  rules TEXT,
  pii TEXT,
  sanitized TEXT,
  latency TEXT,
  seeded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, id DESC);
CREATE TABLE IF NOT EXISTS benchmarks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  json TEXT NOT NULL
);
`);

export const DEFAULT_POLICY = {
  piiMasking: true,
  reversibleRedaction: true,
  injectionDetection: true,
  toxicityDetection: true,
  outputGuard: true,
  strictness: 'medium', // low | medium | high
  aiMode: 'tiered', // off | tiered | always
  failMode: 'closed', // closed | open
};

export function getPolicy(userId) {
  const row = db.prepare('SELECT json FROM policies WHERE user_id=?').get(userId);
  return { ...DEFAULT_POLICY, ...(row ? JSON.parse(row.json) : {}) };
}
export function setPolicy(userId, policy) {
  db.prepare('INSERT INTO policies(user_id,json) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET json=excluded.json').run(
    userId,
    JSON.stringify(policy)
  );
}

export function saveEvent(userId, out, extra = {}) {
  const info = db
    .prepare(
      `INSERT INTO events(user_id,guardrails,action,category,risk,source,reason,rules,pii,sanitized,latency,seeded,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,COALESCE(?,datetime('now')))`
    )
    .run(
      userId,
      out.action === 'UNGUARDED' ? 0 : 1,
      out.action,
      out.category,
      out.risk,
      out.source || null,
      out.reason || null,
      JSON.stringify((out.rules || []).map(({ id, label, explain, w }) => ({ id, label, explain, w }))),
      JSON.stringify([...new Set((out.spans || []).map((s) => s.type))]),
      (out.storedPrompt || '').slice(0, 2000),
      JSON.stringify(out.latency || {}),
      extra.seeded ? 1 : 0,
      extra.createdAt || null
    );
  return info.lastInsertRowid;
}

export const parseEvent = (r) => ({
  ...r,
  rules: JSON.parse(r.rules || '[]'),
  pii: JSON.parse(r.pii || '[]'),
  latency: JSON.parse(r.latency || '{}'),
  guardrails: !!r.guardrails,
  seeded: !!r.seeded,
});
