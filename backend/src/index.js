import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import authRouter from './auth.js';
import routes from './routes.js';
import { seedDemo } from './seed.js';

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: config.corsOrigin === '*' ? true : config.corsOrigin.split(',').map((s) => s.trim()), exposedHeaders: ['x-promptshield-event'] }));
app.use(express.json({ limit: '64kb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60_000, limit: 40, standardHeaders: true, legacyHeaders: false }), authRouter);
app.use(routes);

// Serve the built React app from the same service (single-deploy option).
const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../frontend/dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get(/^(?!\/(api|v1)\/).*/, (_q, s) => s.sendFile(path.join(dist, 'index.html')));
}

app.use((err, _q, res, _n) => {
  console.error(err);
  res.status(err.type === 'entity.parse.failed' ? 400 : 500).json({ error: err.type === 'entity.parse.failed' ? 'Malformed JSON' : 'Internal error' });
});

await seedDemo();
app.listen(config.port, () => console.log(`PromptShield on :${config.port} | AI: ${config.geminiKey ? config.geminiModel : 'regex-only (set GEMINI_API_KEY)'}`));
