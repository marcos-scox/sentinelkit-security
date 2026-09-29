// Detecta a hospedagem para dar a correção no formato certo daquela plataforma.
export function detectPlatform(url, headers) {
  const h = (n) => headers.get(n) || '';
  const host = url.hostname;
  if (host.endsWith('.lovable.app') || host.endsWith('.lovableproject.com')) return 'lovable';
  if (h('x-vercel-id') || /vercel/i.test(h('server'))) return 'vercel';
  if (h('x-nf-request-id') || /netlify/i.test(h('server'))) return 'netlify';
  if (h('rndr-id') || h('x-render-origin-server')) return 'render';
  if (host.endsWith('.github.io') || /github\.com/i.test(h('server'))) return 'github-pages';
  if (h('cf-ray')) return 'cloudflare';
  if (/nginx/i.test(h('server'))) return 'nginx';
  if (/apache/i.test(h('server'))) return 'apache';
  return 'desconhecida';
}

export const PLATFORM_LABEL = {
  lovable: 'Lovable', vercel: 'Vercel', netlify: 'Netlify', render: 'Render',
  'github-pages': 'GitHub Pages', cloudflare: 'Cloudflare', nginx: 'Nginx', apache: 'Apache', desconhecida: 'Não identificada',
};

// Gera o snippet de configuração de headers para a plataforma detectada.
export function headerSnippet(platform, headers) {
  const lines = Object.entries(headers);
  switch (platform) {
    case 'netlify':
      return { lang: 'text', file: 'public/_headers', code: `/*\n${lines.map(([k, v]) => `  ${k}: ${v}`).join('\n')}` };
    case 'vercel':
      return { lang: 'json', file: 'vercel.json', code: JSON.stringify({
        headers: [{ source: '/(.*)', headers: lines.map(([key, value]) => ({ key, value })) }] }, null, 2) };
    case 'nginx':
      return { lang: 'nginx', file: 'nginx.conf (bloco server)', code: lines.map(([k, v]) => `add_header ${k} "${v}" always;`).join('\n') };
    case 'apache':
      return { lang: 'apache', file: '.htaccess', code: lines.map(([k, v]) => `Header always set ${k} "${v}"`).join('\n') };
    case 'render':
      return { lang: 'yaml', file: 'render.yaml (static site)', code: `headers:\n${lines.map(([k, v]) => `  - path: /*\n    name: ${k}\n    value: "${v}"`).join('\n')}` };
    case 'lovable': {
      const csp = headers['Content-Security-Policy'];
      return {
        lang: 'html', file: 'index.html (dentro do <head>)',
        code: csp
          ? `<meta http-equiv="Content-Security-Policy" content="${csp.replace(/;\s*frame-ancestors[^;]*/, '')}">`
          : '<!-- Headers HTTP dependem da hospedagem; veja a observação abaixo -->',
        note: 'Na hospedagem padrão do Lovable nem sempre é possível definir headers HTTP. A CSP pode ir via <meta> no index.html (exceto frame-ancestors). Para HSTS, X-Frame-Options e os demais, use domínio próprio atrás do Cloudflare (Rules → Transform Rules → Modify Response Header) ou publique o build no Netlify/Vercel. Precisa validar o que a sua versão do Lovable permite.',
      };
    }
    case 'cloudflare':
      return { lang: 'text', file: 'Cloudflare → Rules → Transform Rules → Modify Response Header',
        code: lines.map(([k, v]) => `Set static  ${k} = ${v}`).join('\n') };
    default:
      return { lang: 'js', file: 'Node/Express (helmet) ou Fastify (@fastify/helmet)',
        code: `import helmet from '@fastify/helmet';\nawait app.register(helmet, {\n  contentSecurityPolicy: { directives: { /* ver CSP sugerida */ } },\n  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },\n});` };
  }
}
