// Módulo 3 — Secret scanner. Procura credenciais em texto (arquivos ou repo GitHub público).
import { finding, report } from '../lib/finding.js';

const MODULE = 'secrets';

// Regras baseadas em padrões conhecidos (estilo gitleaks). Cada uma: id, severidade, regex, dica.
const RULES = [
  ['aws-access-key', 'critical', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, 'Chave de acesso AWS'],
  ['github-pat', 'critical', /\bghp_[0-9A-Za-z]{36}\b/, 'GitHub Personal Access Token'],
  ['github-oauth', 'critical', /\bgho_[0-9A-Za-z]{36}\b/, 'GitHub OAuth token'],
  ['gitlab-pat', 'critical', /\bglpat-[0-9A-Za-z_-]{20}\b/, 'GitLab Personal Access Token'],
  ['google-api', 'high', /\bAIza[0-9A-Za-z_-]{35}\b/, 'Google API key'],
  ['slack-token', 'high', /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, 'Slack token'],
  ['stripe-secret', 'critical', /\b(sk|rk)_live_[0-9A-Za-z]{20,}\b/, 'Stripe secret key (produção)'],
  ['openai', 'high', /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, 'OpenAI API key'],
  ['supabase-service', 'critical', /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, 'JWT (pode ser service_role Supabase)'],
  ['private-key', 'critical', /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, 'Chave privada'],
  ['twilio', 'high', /\bSK[0-9a-fA-F]{32}\b/, 'Twilio API key'],
  ['sendgrid', 'high', /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/, 'SendGrid API key'],
  ['generic-assign', 'medium',
    /(?:password|passwd|senha|secret|token|api[_-]?key)\s*[:=]\s*['"][^'"\s]{8,}['"]/i,
    'Credencial atribuída no código'],
  ['pix-hardcoded', 'low', /\b\d{11,14}\b(?=.*pix)/i, 'Possível chave PIX numérica hardcoded'],
];

const SKIP_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tar|mp4|mp3|woff2?|ttf|eot|lock|min\.js|map)$/i;
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|vendor|\.next|coverage)\//;

function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  return -Object.values(freq).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0);
}

function redact(match) {
  const s = String(match);
  return s.length <= 10 ? s[0] + '***' : `${s.slice(0, 4)}…${s.slice(-4)} (${s.length} chars)`;
}

export function scanText(path, content) {
  const out = [];
  if (SKIP_PATH.test(`/${path}`) || SKIP_EXT.test(path)) return out;
  const lines = content.split(/\r?\n/);
  const seen = new Set();

  lines.forEach((line, i) => {
    if (line.length > 4000) return;
    for (const [id, severity, rx, label] of RULES) {
      const m = line.match(rx);
      if (!m) continue;
      // Reduz falso positivo: JWT/token genérico só conta com entropia razoável.
      if ((id === 'supabase-service' || id === 'generic-assign') && entropy(m[0]) < 3.5) continue;
      const key = `${id}:${i}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(finding({
        module: MODULE, severity,
        title: `${label} em ${path}:${i + 1}`,
        description: `Padrão de ${label} encontrado no código-fonte.`,
        evidence: redact(m[0]),
        recommendation: 'Remova o segredo do código, rotacione a credencial e use variáveis de ambiente / secret manager. Reescreva o histórico do git se já foi commitado.',
        reference: 'https://docs.github.com/code-security/secret-scanning',
      }));
    }
  });
  return out;
}

// ---------- Repo GitHub público (sem token: usa a API pública, sujeita a rate limit) ----------
async function gh(path) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: { accept: 'application/vnd.github+json', 'user-agent': 'SentinelKit' },
    signal: AbortSignal.timeout(20000),
  });
  if (res.status === 403) throw Object.assign(new Error('Rate limit do GitHub atingido (60/h sem token). Tente mais tarde.'), { statusCode: 429 });
  if (!res.ok) throw Object.assign(new Error(`GitHub respondeu ${res.status} em ${path}`), { statusCode: res.status });
  return res.json();
}

function parseRepo(input) {
  const m = input.match(/github\.com[/:]([^/]+)\/([^/#?.]+)/i) || input.match(/^([^/]+)\/([^/]+)$/);
  if (!m) throw Object.assign(new Error('Informe um repositório GitHub (usuario/repo ou URL).'), { statusCode: 400 });
  return { owner: m[1], repo: m[2].replace(/\.git$/, '') };
}

export async function scanRepo(input, { maxFiles = 300, maxBytes = 400_000 } = {}) {
  const { owner, repo } = parseRepo(input);
  const info = await gh(`/repos/${owner}/${repo}`);
  const branch = info.default_branch;
  const tree = await gh(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);
  const blobs = (tree.tree || [])
    .filter((n) => n.type === 'blob' && n.size <= maxBytes && !SKIP_PATH.test(`/${n.path}`) && !SKIP_EXT.test(n.path))
    .slice(0, maxFiles);

  const findings = [];
  let scanned = 0;
  for (const node of blobs) {
    try {
      const raw = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${node.path}`,
        { headers: { 'user-agent': 'SentinelKit' }, signal: AbortSignal.timeout(15000) });
      if (!raw.ok) continue;
      findings.push(...scanText(node.path, await raw.text()));
      scanned++;
    } catch { /* ignora arquivo */ }
  }

  return report(MODULE, `${owner}/${repo}`, findings, {
    branch, filesInTree: tree.tree?.length ?? 0, filesScanned: scanned,
    truncated: tree.truncated || blobs.length >= maxFiles,
  });
}
