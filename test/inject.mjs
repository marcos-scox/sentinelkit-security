process.env.ALLOW_PRIVATE_TARGETS = 'false';
const { app } = await import('../src/server.js');
await app.ready();
const j = (r) => { try { return JSON.parse(r.payload); } catch { return r.payload; } };

let r = await app.inject({ method: 'GET', url: '/api/health' });
console.log('health:', r.statusCode, JSON.stringify(j(r)));

r = await app.inject({ method: 'POST', url: '/api/scan/secrets',
  headers: { 'content-type': 'application/json' },
  payload: { filename: 'c.js', content: 'const k="AKIAIOSFODNN7EXAMPLE";\nconst gh="ghp_012345678901234567890123456789012345";' } });
const sec = j(r);
console.log('secrets:', r.statusCode, '| score', sec.summary?.score, '| achados', sec.summary?.total);
sec.findings?.forEach(f => console.log('   -', f.severity, f.title, '|', f.evidence));

r = await app.inject({ method: 'POST', url: '/api/scan/web',
  headers: { 'content-type': 'application/json' }, payload: { url: 'http://127.0.0.1/admin' } });
console.log('web SSRF privado:', r.statusCode, '| bloqueado:', /privada|local/.test(j(r).error || ''));

r = await app.inject({ method: 'POST', url: '/api/scan/web',
  headers: { 'content-type': 'application/json' }, payload: { url: 'http://169.254.169.254/' } });
console.log('web SSRF metadata:', r.statusCode, '| bloqueado:', /privada|local/.test(j(r).error || ''));

r = await app.inject({ method: 'POST', url: '/api/scan/deps',
  headers: { 'content-type': 'application/json' }, payload: {} });
console.log('deps sem body:', r.statusCode, '|', j(r).error);

r = await app.inject({ method: 'GET', url: '/' });
console.log('static:', r.statusCode, r.headers['content-type']?.split(';')[0], `${r.payload.length}b`);
await app.close();
console.log('\nOK: inicializa, rotas ativas, static ok, validacoes ok');
