import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';

import { scanDependencies } from './modules/deps.js';
import { scanWeb } from './modules/web/index.js';
import { scanText, scanRepo } from './modules/secrets.js';
import { scanApk } from './modules/apk.js';
import { report } from './lib/finding.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = Fastify({ logger: { level: process.env.LOG_LEVEL || 'info' }, bodyLimit: 15 * 1024 * 1024 });

await app.register(rateLimit, { max: 30, timeWindow: '1 minute' });
await app.register(multipart, { limits: { fileSize: 60 * 1024 * 1024, files: 1 } });
await app.register(fastifyStatic, { root: join(__dirname, '..', 'public') });

// Envelope de erro consistente.
app.setErrorHandler((err, _req, reply) => {
  const code = err.statusCode && err.statusCode < 500 ? err.statusCode : 500;
  if (code >= 500) app.log.error(err);
  reply.code(code).send({ error: err.message || 'Erro interno' });
});

app.get('/api/health', async () => ({ ok: true, version: '0.1.0' }));

// --- Dependências: aceita texto colado (JSON body) ou arquivo (multipart) ---
app.post('/api/scan/deps', async (req) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) {
    const file = await req.file();
    if (!file) throw Object.assign(new Error('Nenhum arquivo enviado.'), { statusCode: 400 });
    const content = (await file.toBuffer()).toString('utf8');
    return scanDependencies(file.filename, content);
  }
  const { filename, content } = req.body || {};
  if (!content) throw Object.assign(new Error('Envie { filename, content } ou um arquivo.'), { statusCode: 400 });
  return scanDependencies(filename || 'package.json', content);
});

// --- Web / headers ---
app.post('/api/scan/web', async (req) => {
  const { url, deepFiles } = req.body || {};
  if (!url) throw Object.assign(new Error('Informe { url }.'), { statusCode: 400 });
  return scanWeb(url, { deepFiles: deepFiles !== false });
});

// --- Secrets: repo GitHub, texto colado ou arquivo ---
app.post('/api/scan/secrets', async (req) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('multipart/form-data')) {
    const file = await req.file();
    if (!file) throw Object.assign(new Error('Nenhum arquivo enviado.'), { statusCode: 400 });
    const content = (await file.toBuffer()).toString('utf8');
    return report('secrets', file.filename, scanText(file.filename, content), { filesScanned: 1 });
  }
  const { repo, filename, content } = req.body || {};
  if (repo) return scanRepo(repo);
  if (content) return report('secrets', filename || 'input.txt', scanText(filename || 'input.txt', content), { filesScanned: 1 });
  throw Object.assign(new Error('Envie { repo }, { filename, content } ou um arquivo.'), { statusCode: 400 });
});

// --- APK (somente multipart) ---
app.post('/api/scan/apk', async (req) => {
  const file = await req.file();
  if (!file) throw Object.assign(new Error('Envie um arquivo .apk.'), { statusCode: 400 });
  const buf = await file.toBuffer();
  return scanApk(buf, file.filename);
});

const port = Number(process.env.PORT) || 3000;
app.listen({ port, host: '0.0.0.0' })
  .then(() => app.log.info(`SentinelKit em http://localhost:${port}`))
  .catch((e) => { app.log.error(e); process.exit(1); });

export { app };
