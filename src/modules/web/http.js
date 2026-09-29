// Cliente HTTP do scanner: segue redirects manualmente, revalidando cada salto contra SSRF,
// e limita o tamanho do corpo lido.
import { assertPublicUrl } from '../../lib/netguard.js';

export const UA = 'Mozilla/5.0 (compatible; SentinelKit/0.2; +https://github.com/) verificador-passivo';

export async function readCapped(res, maxBytes = 2_000_000) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) { chunks.push(value.slice(0, value.length - (total - maxBytes))); await reader.cancel(); break; }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

export async function request(url, { method = 'GET', headers = {}, timeout = 15000 } = {}) {
  return fetch(url, {
    method, redirect: 'manual',
    headers: { 'user-agent': UA, accept: '*/*', ...headers },
    signal: AbortSignal.timeout(timeout),
  });
}

// Segue até 6 redirects, registrando a cadeia. Cada destino passa pela checagem anti-SSRF.
export async function follow(startUrl, opts = {}) {
  const chain = [];
  let url = startUrl;
  for (let i = 0; i < 6; i++) {
    await assertPublicUrl(url);
    const res = await request(url, opts);
    chain.push({ url, status: res.status });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      await res.body?.cancel();
      url = new URL(loc, url).href;
      continue;
    }
    return { res, finalUrl: url, chain };
  }
  throw Object.assign(new Error('Redirecionamentos demais (possível loop).'), { statusCode: 400 });
}
