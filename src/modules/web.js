// Módulo 2 — Configuração web / headers.
// Faz apenas requisições passivas ao alvo (GET/HEAD). Não explora nada.
import { finding, report } from '../lib/finding.js';
import { assertPublicUrl } from '../lib/netguard.js';

const MODULE = 'web';
const UA = 'SentinelKit/0.1 (+https://github.com/) verificador-de-configuracao';

async function req(url, method = 'GET') {
  return fetch(url, {
    method,
    redirect: 'manual',
    headers: { 'user-agent': UA },
    signal: AbortSignal.timeout(15000),
  });
}

function has(headers, name) {
  return headers.get(name) != null;
}

async function checkHeaders(url, findings) {
  let res;
  try {
    res = await req(url.href);
  } catch (e) {
    findings.push(finding({
      module: MODULE, severity: 'info', title: 'Não foi possível conectar ao alvo',
      description: String(e.message || e), recommendation: 'Verifique se a URL está no ar e acessível.',
    }));
    return null;
  }
  const h = res.headers;

  const checks = [
    ['strict-transport-security', 'high', 'HSTS ausente',
      'Sem Strict-Transport-Security, o navegador pode ser induzido a usar HTTP em vez de HTTPS.',
      'Adicione: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
      'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    ['content-security-policy', 'high', 'CSP ausente',
      'Sem Content-Security-Policy, a página fica mais exposta a XSS e injeção de conteúdo.',
      'Defina uma CSP restritiva, começando por default-src \'self\'.',
      'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy'],
    ['x-content-type-options', 'medium', 'X-Content-Type-Options ausente',
      'Sem nosniff, o navegador pode interpretar arquivos com um tipo diferente do declarado.',
      'Adicione: X-Content-Type-Options: nosniff', null],
    ['x-frame-options', 'medium', 'Proteção contra clickjacking ausente',
      'Sem X-Frame-Options (ou frame-ancestors na CSP), a página pode ser embutida em iframe malicioso.',
      'Adicione X-Frame-Options: DENY ou defina frame-ancestors na CSP.', null],
    ['referrer-policy', 'low', 'Referrer-Policy ausente',
      'A URL de origem pode vazar para terceiros na navegação.',
      'Adicione: Referrer-Policy: strict-origin-when-cross-origin', null],
    ['permissions-policy', 'low', 'Permissions-Policy ausente',
      'Recursos como câmera, microfone e geolocalização ficam sem restrição explícita.',
      'Defina uma Permissions-Policy limitando os recursos usados.', null],
  ];

  for (const [name, severity, title, description, recommendation, reference] of checks) {
    if (!has(h, name)) findings.push(finding({ module: MODULE, severity, title, description, recommendation, reference }));
  }

  // CSP fraca
  const csp = h.get('content-security-policy');
  if (csp && /unsafe-inline|unsafe-eval|\*(?!\.)/.test(csp)) {
    findings.push(finding({
      module: MODULE, severity: 'medium', title: 'CSP presente mas permissiva',
      description: 'A CSP contém unsafe-inline, unsafe-eval ou curinga "*", o que reduz muito sua eficácia.',
      evidence: csp.slice(0, 200), recommendation: 'Remova unsafe-* e curingas; prefira nonces ou hashes.',
    }));
  }

  // Vazamento de tecnologia
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version']) {
    const val = h.get(name);
    if (val && /\d/.test(val)) {
      findings.push(finding({
        module: MODULE, severity: 'low', title: `Versão de software exposta no header ${name}`,
        description: 'Divulgar versão exata facilita a busca por exploits específicos daquela versão.',
        evidence: `${name}: ${val}`, recommendation: `Oculte ou generalize o header ${name}.`,
      }));
    }
  }

  // Cookies
  const setCookie = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  for (const c of setCookie) {
    const flags = c.toLowerCase();
    const nm = c.split('=')[0];
    const missing = ['secure', 'httponly'].filter((f) => !flags.includes(f));
    if (missing.length || !/samesite=/.test(flags)) {
      findings.push(finding({
        module: MODULE, severity: 'medium', title: `Cookie "${nm}" com flags de segurança incompletas`,
        description: `Faltando: ${[...missing, /samesite=/.test(flags) ? null : 'samesite'].filter(Boolean).join(', ')}.`,
        evidence: c.slice(0, 120),
        recommendation: 'Defina Secure, HttpOnly e SameSite=Lax/Strict nos cookies de sessão.',
      }));
    }
  }

  return res;
}

async function checkHttpsRedirect(url, findings) {
  if (url.protocol !== 'https:') return;
  const httpUrl = new URL(url.href);
  httpUrl.protocol = 'http:';
  try {
    const res = await req(httpUrl.href, 'HEAD');
    const loc = res.headers.get('location') || '';
    if (!(res.status >= 300 && res.status < 400 && loc.startsWith('https:'))) {
      findings.push(finding({
        module: MODULE, severity: 'medium', title: 'HTTP não redireciona para HTTPS',
        description: 'O acesso via http:// não é redirecionado para https://, permitindo tráfego em claro.',
        recommendation: 'Force redirect 301 de HTTP para HTTPS no servidor/proxy.',
      }));
    }
  } catch { /* alvo pode não escutar em 80; ignora */ }
}

const EXPOSED = [
  ['/.git/HEAD', 'high', 'Repositório .git exposto', /ref:\s|^[0-9a-f]{40}/m,
    'O diretório .git acessível permite baixar o código-fonte completo. Bloqueie o acesso a /.git/ no servidor.'],
  ['/.env', 'critical', 'Arquivo .env exposto', /=/,
    'Arquivos .env costumam conter senhas e chaves. Remova do webroot e bloqueie o acesso imediatamente.'],
  ['/.aws/credentials', 'critical', 'Credenciais AWS expostas', /aws_access_key/i,
    'Remova o arquivo do servidor e rotacione as chaves AWS.'],
  ['/config.php.bak', 'high', 'Backup de configuração exposto', /./,
    'Remova arquivos de backup (.bak, .old, ~) do webroot.'],
  ['/.DS_Store', 'low', '.DS_Store exposto', /Bud1|\x00/, 'Revela nomes de arquivos internos. Remova do servidor.'],
];

async function checkExposedFiles(url, findings) {
  for (const [path, severity, title, pattern, recommendation] of EXPOSED) {
    try {
      const res = await req(new URL(path, url.origin).href);
      if (res.status !== 200) continue;
      const body = (await res.text()).slice(0, 4096);
      if (pattern.test(body)) {
        findings.push(finding({
          module: MODULE, severity, title, description: `Arquivo acessível publicamente em ${path}.`,
          evidence: `${path} → HTTP 200`, recommendation,
        }));
      }
    } catch { /* ignora timeouts por arquivo */ }
  }
}

export async function scanWeb(rawUrl, { deepFiles = true } = {}) {
  const url = await assertPublicUrl(rawUrl);
  const findings = [];
  const res = await checkHeaders(url, findings);
  if (res) {
    await checkHttpsRedirect(url, findings);
    if (deepFiles) await checkExposedFiles(url, findings);
  }
  return report(MODULE, url.href, findings, {
    finalStatus: res?.status ?? null,
    server: res?.headers.get('server') ?? null,
  });
}
