import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { z } from 'zod';
import { Router } from 'express';
import { db } from './db.js';
import { config } from './config.js';

export const validate = (schema) => (req, res, next) => {
  const r = schema.safeParse(req.body);
  if (!r.success) return res.status(400).json({ error: 'Invalid input', details: r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`) });
  req.body = r.data;
  next();
};

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const sign = (u) => jwt.sign({ sub: u.id, email: u.email }, config.jwtSecret, { expiresIn: '7d' });
const newKey = () => 'ps_' + crypto.randomBytes(24).toString('hex');

// Accepts a JWT (dashboard) or a ps_ API key (drop-in proxy clients).
export function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    if (token.startsWith('ps_')) {
      const u = db.prepare('SELECT id,email FROM users WHERE api_key_hash=?').get(sha(token));
      if (!u) return res.status(401).json({ error: 'Invalid API key' });
      req.user = u;
    } else {
      const p = jwt.verify(token, config.jwtSecret);
      req.user = { id: p.sub, email: p.email };
    }
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const creds = z.object({ email: z.string().email().max(120).transform((s) => s.toLowerCase()), password: z.string().min(8, 'min 8 characters').max(100) });
const router = Router();

router.post('/register', validate(creds), async (req, res) => {
  const { email, password } = req.body;
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'Email already registered' });
  const key = newKey();
  const info = db.prepare('INSERT INTO users(email,password_hash,api_key_hash) VALUES(?,?,?)').run(email, await bcrypt.hash(password, 10), sha(key));
  const user = { id: Number(info.lastInsertRowid), email };
  res.status(201).json({ token: sign(user), user, apiKey: key });
});

router.post('/login', validate(creds), async (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: sign(u), user: { id: u.id, email: u.email } });
});

router.get('/me', auth, (req, res) => res.json({ user: req.user }));

router.post('/apikey', auth, (req, res) => {
  const key = newKey();
  db.prepare('UPDATE users SET api_key_hash=? WHERE id=?').run(sha(key), req.user.id);
  res.json({ apiKey: key, note: 'Shown once. Store it securely.' });
});

export default router;
