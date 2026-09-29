// Procura arquivos e rotas sensíveis expostos, e checa cookies/segredos no HTML da home.
import { finding, pass } from '../../lib/finding.js';
import { scanText } from '../secrets.js';

const M = 'web';
const CAT = 'Exposição';

// [caminho, severidade, título, regex-de-confirmação, recomendação]
const PATHS = [
  ['/.env', 'critical', 'Arquivo .env exposto', /^\s*[A-Z0-9_]+\s*=/m, 'Remova .env do webroot e rotacione todas as credenciais que estavam nele.'],
  ['/.git/config', 'high', 'Repositório .git exposto', /\[core\]|repositoryformatversion/, 'Bloqueie o acesso a /.git/ no servidor/CDN. O código-fonte inteiro pode ser reconstruído.'],
  ['/.git/HEAD', 'high', 'Repositório .git exposto', /ref:\s|^[0-9a-f]{40}/m, 'Bloqueie o acesso a /.git/. É possível baixar todo o histórico do repositório.'],
  ['/.svn/entries', 'high', 'Diretório .svn exposto', /./, 'Bloqueie o acesso a /.svn/.'],
  ['/.aws/credentials', 'critical', 'Credenciais AWS expostas', /aws_access_key_id/i, 'Remova o arquivo e rotacione as chaves AWS imediatamente.'],
  ['/.DS_Store', 'low', '.DS_Store exposto', /Bud1/, 'Revela nomes de arquivos internos. Remova do servidor.'],
  ['/config.php.bak', 'high', 'Backup de configuração exposto', /<\?php|=/, 'Remova arquivos .bak/.old/~ do webroot.'],
  ['/backup.sql', 'critical', 'Dump de banco exposto', /INSERT INTO|CREATE TABLE/i, 'Remova dumps SQL do webroot imediatamente.'],
  ['/.env.local', 'critical', 'Arquivo .env.local exposto', /=/, 'Remova do webroot e rotacione credenciais.'],
  ['/wp-config.php.bak', 'critical', 'Backup do wp-config exposto', /DB_PASSWORD|DB_NAME/, 'Remova o backup e rotacione as credenciais do banco.'],
  ['/phpinfo.php', 'medium', 'phpinfo() exposto', /phpinfo\(\)|PHP Version/i, 'Remova o arquivo — ele revela caminhos, versões e configuração do servidor.'],
  ['/server-status', 'medium', 'Apache server-status exposto', /Apache Server Status/i, 'Restrinja /server-status a IPs internos.'],
  ['/.well-known/security.txt', 'info-good', 'security.txt presente', /contact/i, ''],
];

const API_DOCS = [
  ['/swagger.json', 'Documentação de API (Swagger) exposta', /"swagger"|"openapi"/],
  ['/openapi.json', 'Documentação de API (OpenAPI) exposta', /"openapi"/],
  ['/api/swagger.json', 'Documentação de API exposta', /"swagger"|"openapi"/],
  ['/graphql', 'Endpoint GraphQL acessível', /__schema|graphql|errors/i],
];

async function probe(base, path, request) {
  try {
    const res = await request(new URL(path, base.origin).href, { timeout: 8000 });
    const status = res.status;
    let body = '';
    if (status === 200) {
      const r = res.body?.getReader();
      if (r) { const { value } = await r.read(); body = value ? Buffer.from(value).toString('utf8').slice(0, 4096) : ''; await r.cancel(); }
    } else { await res.body?.cancel(); }
    return { status, body };
  } catch { return { status: 0, body: '' }; }
}

export async function checkExposure(url, request, findings, passed, robots) {
  let anyLeak = false;
  for (const [path, severity, title, pattern, recommendation] of PATHS) {
    const { status, body } = await probe(url, path, request);
    if (status !== 200 || !pattern.test(body)) continue;
    if (severity === 'info-good') { passed.push(pass('Boas práticas', 'security.txt publicado', path)); continue; }
    anyLeak = true;
    findings.push(finding({ module: M, severity, category: CAT, title,
      description: `Acessível publicamente em ${path} (HTTP 200).`,
      impact: severity === 'critical' ? 'Exposição direta de credenciais ou dados — risco imediato.' : undefined,
      evidence: `${path} → 200`, recommendation }));
  }

  for (const [path, title, pattern] of API_DOCS) {
    const { status, body } = await probe(url, path, request);
    if (status === 200 && pattern.test(body)) {
      findings.push(finding({ module: M, severity: 'low', category: CAT, title,
        description: `${path} responde publicamente. Documentação/described schema facilita mapear a superfície de ataque da API.`,
        evidence: `${path} → 200`, recommendation: 'Restrinja o acesso em produção se a API não for pública.' }));
    }
  }

  // Rotas administrativas citadas no robots.txt (fonte comum de "caminhos escondidos")
  if (robots) {
    const disallow = [...robots.matchAll(/disallow:\s*(\S+)/gi)].map((m) => m[1]).filter((p) => /admin|dashboard|painel|private|api|config|backup/i.test(p)).slice(0, 8);
    if (disallow.length) {
      findings.push(finding({ module: M, severity: 'info', category: CAT, title: 'robots.txt revela caminhos sensíveis',
        description: 'O robots.txt lista rotas que talvez a intenção fosse manter discretas — mas ele é público e legível por qualquer um.',
        evidence: disallow.join(', '), recommendation: 'Não confie no robots.txt como controle de acesso; proteja as rotas com autenticação.' }));
    }
  }

  if (!anyLeak) passed.push(pass(CAT, 'Nenhum arquivo sensível comum exposto', '.env, .git, backups, dumps'));
}

// Analisa o HTML da própria home em busca de segredos embutidos e apontadores úteis.
export function checkHomepage(html, findings, passed) {
  const secretFindings = scanText('página inicial (HTML)', html).map((f) => ({
    ...f, module: M, category: 'Segredos no cliente',
    impact: 'Qualquer visitante lê o código-fonte da página; um segredo aqui é público.',
  }));
  findings.push(...secretFindings);
  if (!secretFindings.length) passed.push(pass('Segredos no cliente', 'Nenhum segredo óbvio no HTML da home'));

  // Sourcemaps em produção
  const maps = [...html.matchAll(/\/\/[#@]\s*sourceMappingURL=(\S+\.map)/g)].map((m) => m[1]);
  if (maps.length) {
    findings.push(finding({ module: M, severity: 'low', category: 'Informação',
      title: 'Source maps referenciados em produção',
      description: 'Arquivos .map permitem reconstruir o código-fonte original (não minificado) da aplicação.',
      evidence: maps.slice(0, 3).join(', '), recommendation: 'Não publique .map em produção, ou restrinja o acesso a eles.' }));
  }

  // Comentários com pistas
  const comments = [...html.matchAll(/<!--([\s\S]{0,300}?)-->/g)].map((m) => m[1])
    .filter((c) => /todo|fixme|senha|password|api[_-]?key|secret|debug|test|remover|hack/i.test(c));
  if (comments.length) {
    findings.push(finding({ module: M, severity: 'info', category: 'Informação',
      title: 'Comentários HTML com pistas de desenvolvimento',
      description: 'Comentários deixados no HTML podem revelar rotas, credenciais ou lógica interna.',
      evidence: comments[0].trim().slice(0, 120), recommendation: 'Remova comentários sensíveis no build de produção.' }));
  }
}
