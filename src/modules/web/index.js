// Orquestrador do scanner web. Faz uma passada passiva e completa sobre o alvo.
import { finding, pass, report } from '../../lib/finding.js';
import { assertPublicUrl } from '../../lib/netguard.js';
import { follow, request, readCapped } from './http.js';
import { checkTls } from './tls.js';
import { checkHeaders, checkCors } from './headers.js';
import { checkExposure, checkHomepage } from './exposure.js';
import { detectPlatform, PLATFORM_LABEL, headerSnippet } from './platform.js';
import { vulnFindings } from '../deps.js';

const M = 'web';

async function fetchText(url) {
  try {
    const res = await request(url, { timeout: 8000 });
    if (res.status !== 200) { await res.body?.cancel(); return null; }
    return await readCapped(res, 500_000);
  } catch { return null; }
}

// SPAs (Lovable, Vite, CRA) servem o app via bundle JS. Tenta achar libs vulneráveis conhecidas no bundle.
async function checkSpaBundle(url, html, findings, passed, meta) {
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const isSpa = /<div id=["'](root|app)["']>\s*<\/div>/i.test(html) || /vite|__vite|type=["']module["']/i.test(html);
  if (isSpa) meta.spa = true;

  const assets = scripts.map((s) => new URL(s, url).href).filter((u) => /\.js($|\?)/.test(u)).slice(0, 6);
  const libFindings = [];
  const detected = new Set();
  const LIB_RX = [
    ['react', 'npm', /react(?:-dom)?["']?\s*version["']?\s*[:=]\s*["']?(\d+\.\d+\.\d+)/i],
    ['lodash', 'npm', /lodash[\s\S]{0,40}?VERSION\s*=\s*["'](\d+\.\d+\.\d+)/i],
    ['axios', 'npm', /axios[\s\S]{0,30}?["']?version["']?\s*[:=]\s*["'](\d+\.\d+\.\d+)/i],
    ['jquery', 'npm', /jquery["']?\s*[:=]\s*["']?(\d+\.\d+\.\d+)|jQuery\.fn\.jquery\s*=\s*["'](\d+\.\d+\.\d+)/i],
  ];
  for (const asset of assets) {
    const js = await fetchText(asset);
    if (!js) continue;
    for (const [name, ecosystem, rx] of LIB_RX) {
      const m = js.match(rx);
      const version = m && (m[1] || m[2]);
      if (version && !detected.has(name)) { detected.add(name); libFindings.push({ name, version, ecosystem, source: 'bundle JS' }); }
    }
  }
  if (libFindings.length) {
    meta.detectedLibs = libFindings.map((l) => `${l.name}@${l.version}`);
    try {
      const { findings: vf } = await vulnFindings(libFindings, M);
      if (vf.length) findings.push(...vf.map((f) => ({ ...f, category: 'Componentes vulneráveis (front-end)' })));
      else passed.push(pass('Componentes', 'Libs JS detectadas sem CVE conhecida', meta.detectedLibs.join(', ')));
    } catch { /* OSV indisponível */ }
  }
}

function overallNote(platform, recommended, findings, meta) {
  if (!Object.keys(recommended).length) return null;
  const snippet = headerSnippet(platform, {
    ...recommended,
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  });
  return { platform: PLATFORM_LABEL[platform], recommendedHeaders: recommended, snippet };
}

export async function scanWeb(rawUrl, { deepFiles = true, checkCors: doCors = true } = {}) {
  const startUrl = await assertPublicUrl(rawUrl);
  const findings = [];
  const passed = [];
  const meta = {};

  // Redirecionamento HTTP → HTTPS
  if (startUrl.protocol === 'https:') {
    const httpU = new URL(startUrl.href); httpU.protocol = 'http:';
    try {
      const r = await request(httpU.href, { method: 'HEAD', timeout: 8000 });
      await r.body?.cancel();
      const loc = r.headers.get('location') || '';
      if (r.status >= 300 && r.status < 400 && loc.startsWith('https:')) passed.push(pass('Transporte', 'HTTP redireciona para HTTPS'));
      else if (r.status < 400) findings.push(finding({ module: M, severity: 'medium', category: 'Transporte', title: 'HTTP não redireciona para HTTPS',
        description: 'O acesso por http:// responde sem forçar o redirecionamento para https://.',
        recommendation: 'Configure redirect 301 permanente de HTTP para HTTPS.' }));
    } catch { /* porta 80 fechada é ok */ }
  }

  // Requisição principal (seguindo redirects)
  let res, finalUrl, chain;
  try {
    ({ res, finalUrl, chain } = await follow(startUrl.href));
  } catch (e) {
    findings.push(finding({ module: M, severity: 'info', category: 'Conexão', title: 'Não foi possível acessar o alvo',
      description: String(e.message || e), recommendation: 'Confirme se a URL está no ar e acessível externamente.' }));
    return report(M, startUrl.href, findings, meta, passed);
  }
  const url = new URL(finalUrl);
  meta.finalStatus = res.status;
  meta.redirects = chain.length > 1 ? chain : undefined;

  const platform = detectPlatform(url, res.headers);
  meta.platform = PLATFORM_LABEL[platform];
  meta.server = res.headers.get('server') || null;

  const html = await readCapped(res, 1_500_000);

  // TLS (paralelizável com o resto)
  const [tlsRes] = await Promise.all([checkTls(url, M)]);
  findings.push(...tlsRes.findings); passed.push(...tlsRes.passed);
  if (tlsRes.info) meta.tls = tlsRes.info;

  // Headers / CSP / cookies
  const recommended = checkHeaders(url, res, platform, findings, passed);

  // CORS
  if (doCors) await checkCors(url, request, findings, passed);

  // HTML da home
  if (html) checkHomepage(html, findings, passed);

  // Arquivos expostos + robots
  if (deepFiles) {
    const robots = await fetchText(new URL('/robots.txt', url.origin).href);
    await checkExposure(url, request, findings, passed, robots);
  }

  // Bundle SPA / libs vulneráveis
  if (html) await checkSpaBundle(url, html, findings, passed, meta);

  meta.overview = overallNote(platform, recommended, findings, meta);
  return report(M, url.href, findings, meta, passed);
}
