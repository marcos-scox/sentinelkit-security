// Análise detalhada de headers de segurança, incluindo parsing de HSTS e CSP.
import { finding, pass } from '../../lib/finding.js';

const M = 'web';

export function parseCsp(csp) {
  const out = {};
  for (const part of csp.split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) out[name.toLowerCase()] = vals;
  }
  return out;
}

function analyzeCsp(csp, findings, passed) {
  const CAT = 'CSP';
  const d = parseCsp(csp);
  const script = d['script-src'] || d['default-src'] || [];
  const problems = [];
  if (script.includes("'unsafe-inline'") && !script.some((v) => v.startsWith("'nonce-") || v.startsWith("'sha"))) {
    problems.push(['high', "script-src permite 'unsafe-inline'", 'Scripts inline injetados via XSS são executados normalmente — a CSP praticamente não protege contra XSS.', "Remova 'unsafe-inline' de script-src e use nonces ou hashes."]);
  }
  if (script.includes("'unsafe-eval'")) {
    problems.push(['medium', "script-src permite 'unsafe-eval'", 'Permite eval()/new Function(), frequentemente usados em cadeias de XSS.', "Remova 'unsafe-eval' se o app não depender dele."]);
  }
  if (script.some((v) => v === '*' || v === 'https:' || v === 'http:' || v === 'data:')) {
    problems.push(['high', 'script-src aceita qualquer origem', 'Curingas como *, https: ou data: permitem carregar script de qualquer lugar.', 'Liste explicitamente as origens de script confiáveis.']);
  }
  if (!d['object-src'] && !(d['default-src'] || []).includes("'none'")) {
    problems.push(['low', 'CSP sem object-src', 'Plugins (<object>/<embed>) continuam permitidos.', "Adicione object-src 'none'."]);
  }
  if (!d['base-uri']) {
    problems.push(['low', 'CSP sem base-uri', 'Um atacante com injeção de HTML pode trocar a <base> e redirecionar scripts relativos.', "Adicione base-uri 'self'."]);
  }
  if (!d['frame-ancestors']) {
    problems.push(['info', 'CSP sem frame-ancestors', 'Proteção contra clickjacking depende só do X-Frame-Options.', "Adicione frame-ancestors 'none' (ou 'self')."]);
  }
  if (!d['form-action']) {
    problems.push(['info', 'CSP sem form-action', 'Formulários injetados podem enviar dados para qualquer destino.', "Adicione form-action 'self'."]);
  }
  for (const [severity, title, description, recommendation] of problems) {
    findings.push(finding({ module: M, severity, category: CAT, title, description, evidence: csp.slice(0, 300), recommendation,
      reference: 'https://csp-evaluator.withgoogle.com/' }));
  }
  if (!problems.some(([s]) => s === 'high' || s === 'medium')) passed.push(pass(CAT, 'CSP sem permissões perigosas em script-src'));
}

function analyzeHsts(value, findings, passed) {
  const CAT = 'Headers';
  const maxAge = Number((value.match(/max-age=(\d+)/i) || [])[1] || 0);
  const sub = /includesubdomains/i.test(value);
  const pre = /preload/i.test(value);
  if (maxAge < 15552000) {
    findings.push(finding({ module: M, severity: 'low', category: CAT, title: `HSTS com max-age curto (${Math.round(maxAge / 86400)} dias)`,
      description: 'Abaixo de 180 dias, a proteção expira rápido para visitantes que não retornam com frequência.',
      evidence: `Strict-Transport-Security: ${value}`,
      recommendation: 'Use max-age=63072000 (2 anos) após confirmar que todo o site funciona em HTTPS.' }));
  } else {
    passed.push(pass(CAT, 'HSTS com validade adequada', `${Math.round(maxAge / 86400)} dias${sub ? ', includeSubDomains' : ''}${pre ? ', preload' : ''}`));
  }
  if (!sub) {
    findings.push(finding({ module: M, severity: 'info', category: CAT, title: 'HSTS sem includeSubDomains',
      description: 'Subdomínios não herdam a obrigatoriedade de HTTPS.', evidence: value,
      recommendation: 'Adicione includeSubDomains se todos os subdomínios usam HTTPS.' }));
  }
}

export function checkHeaders(url, res, platform, findings, passed) {
  const h = res.headers;
  const CAT = 'Headers';
  const isHttps = url.protocol === 'https:';

  // HSTS
  const hsts = h.get('strict-transport-security');
  if (isHttps && !hsts) {
    findings.push(finding({ module: M, severity: 'medium', category: CAT, title: 'HSTS ausente',
      description: 'Sem Strict-Transport-Security, o primeiro acesso por http:// pode ser interceptado e rebaixado (SSL stripping).',
      impact: 'Em redes hostis, um atacante consegue manter a vítima em HTTP e ler o tráfego.',
      recommendation: 'Envie Strict-Transport-Security: max-age=63072000; includeSubDomains',
      reference: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security' }));
  } else if (hsts) analyzeHsts(hsts, findings, passed);

  // CSP
  const csp = h.get('content-security-policy');
  const cspRO = h.get('content-security-policy-report-only');
  if (csp) {
    passed.push(pass('CSP', 'Content-Security-Policy presente'));
    analyzeCsp(csp, findings, passed);
  } else {
    findings.push(finding({ module: M, severity: 'high', category: 'CSP', title: cspRO ? 'CSP apenas em modo report-only' : 'CSP ausente',
      description: cspRO ? 'A política só reporta violações, não bloqueia nada.' : 'Sem Content-Security-Policy, qualquer script injetado (XSS) roda sem restrição.',
      impact: 'Em caso de XSS, o atacante pode roubar sessão/tokens do localStorage (ex.: token Supabase) e agir como o usuário.',
      recommendation: 'Aplique a CSP sugerida no painel de visão geral, testando antes em report-only.',
      reference: 'https://developer.mozilla.org/docs/Web/HTTP/CSP' }));
  }

  // Clickjacking
  const xfo = h.get('x-frame-options');
  const fa = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !fa) {
    findings.push(finding({ module: M, severity: 'medium', category: CAT, title: 'Proteção contra clickjacking ausente',
      description: 'Sem X-Frame-Options nem frame-ancestors, a página pode ser embutida em um iframe de outro site.',
      impact: 'Um site malicioso pode sobrepor botões invisíveis e induzir o usuário logado a clicar em ações reais.',
      recommendation: "Envie X-Frame-Options: DENY ou frame-ancestors 'none' na CSP." }));
  } else passed.push(pass(CAT, 'Proteção contra clickjacking', xfo ? `X-Frame-Options: ${xfo}` : 'frame-ancestors na CSP'));

  // Simples
  const simple = [
    ['x-content-type-options', (v) => /nosniff/i.test(v), 'low', 'X-Content-Type-Options ausente',
      'O navegador pode "adivinhar" o tipo de um arquivo e executá-lo como script.', 'Envie X-Content-Type-Options: nosniff'],
    ['referrer-policy', (v) => !/unsafe-url|no-referrer-when-downgrade/i.test(v), 'low', 'Referrer-Policy ausente ou fraca',
      'A URL completa (com parâmetros, IDs, tokens) pode vazar para sites de terceiros.', 'Envie Referrer-Policy: strict-origin-when-cross-origin'],
    ['permissions-policy', () => true, 'low', 'Permissions-Policy ausente',
      'Câmera, microfone e geolocalização ficam sem restrição explícita, inclusive para iframes de terceiros.',
      'Envie Permissions-Policy: camera=(), microphone=(), geolocation=()'],
    ['cross-origin-opener-policy', () => true, 'info', 'Cross-Origin-Opener-Policy ausente',
      'Janelas abertas por outros sites mantêm referência à sua página (window.opener).', 'Envie Cross-Origin-Opener-Policy: same-origin'],
  ];
  for (const [name, ok, severity, title, description, recommendation] of simple) {
    const v = h.get(name);
    if (!v || !ok(v)) findings.push(finding({ module: M, severity, category: CAT, title, description, recommendation, evidence: v ? `${name}: ${v}` : null }));
    else passed.push(pass(CAT, name, v));
  }

  // Divulgação de informação
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'via']) {
    const v = h.get(name);
    if (!v) continue;
    const versioned = /\d+\.\d+/.test(v);
    if (versioned || name === 'x-powered-by') {
      findings.push(finding({ module: M, severity: versioned ? 'low' : 'info', category: 'Informação',
        title: `Tecnologia exposta no header ${name}`,
        description: versioned ? 'Versão exata divulgada — facilita procurar exploits específicos.' : 'Revela a stack usada.',
        evidence: `${name}: ${v}`, recommendation: `Remova ou generalize o header ${name}.` }));
    }
  }

  // Cache de páginas com dados
  const cc = h.get('cache-control') || '';
  if (/public/i.test(cc) && h.get('set-cookie')) {
    findings.push(finding({ module: M, severity: 'medium', category: CAT, title: 'Resposta com cookie marcada como cache público',
      description: 'Proxies/CDNs podem armazenar e servir a resposta (e o cookie) para outros usuários.',
      evidence: `cache-control: ${cc}`, recommendation: 'Use Cache-Control: private, no-store em respostas autenticadas.' }));
  }

  // Cookies
  const cookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  if (!cookies.length) passed.push(pass('Cookies', 'Nenhum cookie definido na página inicial'));
  for (const c of cookies) {
    const lower = c.toLowerCase();
    const name = c.split('=')[0].trim();
    const missing = [];
    if (isHttps && !/;\s*secure/.test(lower)) missing.push('Secure');
    if (!/;\s*httponly/.test(lower)) missing.push('HttpOnly');
    if (!/;\s*samesite=/.test(lower)) missing.push('SameSite');
    const sensitive = /sess|auth|token|jwt|sid|login/i.test(name);
    if (missing.length) {
      findings.push(finding({ module: M, severity: sensitive ? 'medium' : 'low', category: 'Cookies',
        title: `Cookie "${name}" sem ${missing.join(', ')}`,
        description: `${missing.includes('HttpOnly') ? 'Acessível via JavaScript (roubo por XSS). ' : ''}${missing.includes('Secure') ? 'Pode ser enviado por HTTP em claro. ' : ''}${missing.includes('SameSite') ? 'Enviado em requisições de outros sites (CSRF).' : ''}`.trim(),
        evidence: c.replace(/=([^;]{6})[^;]*/, '=$1…').slice(0, 140),
        recommendation: 'Defina Secure; HttpOnly; SameSite=Lax (ou Strict) nos cookies.' }));
    } else passed.push(pass('Cookies', `Cookie "${name}" com flags corretas`));
    if (/samesite=none/.test(lower) && !/;\s*secure/.test(lower)) {
      findings.push(finding({ module: M, severity: 'low', category: 'Cookies', title: `Cookie "${name}" com SameSite=None sem Secure`,
        description: 'Navegadores modernos rejeitam essa combinação.', recommendation: 'Adicione Secure.' }));
    }
  }

  // Monta conjunto recomendado de headers ausentes (para snippet por plataforma)
  const recommended = {};
  if (isHttps && !hsts) recommended['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains';
  if (!xfo) recommended['X-Frame-Options'] = 'DENY';
  if (!h.get('x-content-type-options')) recommended['X-Content-Type-Options'] = 'nosniff';
  if (!h.get('referrer-policy')) recommended['Referrer-Policy'] = 'strict-origin-when-cross-origin';
  if (!h.get('permissions-policy')) recommended['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';
  return recommended;
}

export async function checkCors(url, request, findings, passed) {
  const CAT = 'CORS';
  const evil = 'https://sentinelkit-cors-probe.example';
  try {
    const res = await request(url.href, { headers: { origin: evil } });
    await res.body?.cancel();
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials') === 'true';
    if (acao === evil) {
      findings.push(finding({ module: M, severity: acac ? 'high' : 'medium', category: CAT,
        title: acac ? 'CORS reflete qualquer origem com credenciais' : 'CORS reflete qualquer origem',
        description: 'O servidor devolve no Access-Control-Allow-Origin a origem que o visitante enviar.',
        impact: acac ? 'Qualquer site pode fazer requisições autenticadas em nome do usuário e ler a resposta.' : 'Qualquer site pode ler as respostas desta URL.',
        evidence: `Origin: ${evil} → ACAO: ${acao}${acac ? ', Allow-Credentials: true' : ''}`,
        recommendation: 'Use uma lista fixa de origens permitidas.' }));
    } else if (acao === '*') {
      findings.push(finding({ module: M, severity: 'info', category: CAT, title: 'CORS aberto (*)',
        description: 'Qualquer site pode ler as respostas públicas desta URL. Aceitável para conteúdo público, não para APIs com dados.',
        evidence: 'Access-Control-Allow-Origin: *', recommendation: 'Restrinja se a rota retornar dados de usuários.' }));
    } else {
      passed.push(pass(CAT, 'CORS não reflete origens arbitrárias'));
    }
    const nres = await request(url.href, { headers: { origin: 'null' } });
    await nres.body?.cancel();
    if (nres.headers.get('access-control-allow-origin') === 'null') {
      findings.push(finding({ module: M, severity: 'medium', category: CAT, title: 'CORS aceita a origem "null"',
        description: 'Iframes sandbox e arquivos locais enviam Origin: null — qualquer atacante consegue forjá-la.',
        recommendation: 'Nunca inclua "null" na lista de origens permitidas.' }));
    }
  } catch { /* ignora */ }
}
