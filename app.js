const API_BASE = (window.SENTINELKIT_API || '').replace(/\/$/, '');
const $ = (s, r = document) => r.querySelector(s);
const el = (t, a = {}, ...kids) => {
  const n = document.createElement(t);
  for (const [k, v] of Object.entries(a)) k === 'class' ? (n.className = v) : k === 'html' ? (n.innerHTML = v) : n.setAttribute(k, v);
  for (const c of kids) n.append(c?.nodeType ? c : document.createTextNode(c ?? ''));
  return n;
};

const SEV = {
  critical: { c: 'var(--crit)', label: 'crítico' }, high: { c: 'var(--high)', label: 'alto' },
  medium: { c: 'var(--med)', label: 'médio' }, low: { c: 'var(--low)', label: 'baixo' },
  info: { c: 'var(--info)', label: 'info' },
};

const PANELS = {
  deps: {
    intro: 'Analisa dependências vulneráveis via base pública OSV.dev. Envie um lockfile para resultado exato.',
    render: (p) => {
      const ta = el('textarea', { placeholder: 'Cole o conteúdo de package.json, package-lock.json ou requirements.txt…' });
      const file = fileInput('.json,.txt', 'package-lock.json, package.json ou requirements.txt');
      p.append(field('Colar manifesto', ta), orSep(), file.node,
        actions(async () => {
          if (file.file) return post('/api/scan/deps', file.file);
          if (!ta.value.trim()) throw new Error('Cole um manifesto ou selecione um arquivo.');
          return postJson('/api/scan/deps', { filename: guessName(ta.value), content: ta.value });
        }));
    },
  },
  web: {
    intro: 'Verifica headers de segurança, redirecionamento HTTPS, cookies e arquivos expostos. Só requisições passivas.',
    render: (p) => {
      const url = el('input', { type: 'text', placeholder: 'https://exemplo.com.br' });
      p.append(field('URL do alvo', url),
        actions(async () => {
          if (!url.value.trim()) throw new Error('Informe a URL.');
          return postJson('/api/scan/web', { url: url.value.trim() });
        }));
    },
  },
  secrets: {
    intro: 'Procura chaves de API, tokens e senhas expostas em um repositório GitHub público ou em texto/arquivo.',
    render: (p) => {
      const repo = el('input', { type: 'text', placeholder: 'usuario/repo ou https://github.com/usuario/repo' });
      const ta = el('textarea', { placeholder: 'Ou cole código/config para verificar…' });
      const file = fileInput('*', 'qualquer arquivo de texto/código');
      p.append(field('Repositório GitHub público', repo), orSep(), field('Colar texto', ta), orSep(), file.node,
        actions(async () => {
          if (repo.value.trim()) return postJson('/api/scan/secrets', { repo: repo.value.trim() });
          if (file.file) return post('/api/scan/secrets', file.file);
          if (ta.value.trim()) return postJson('/api/scan/secrets', { filename: 'input.txt', content: ta.value });
          throw new Error('Informe um repo, cole texto ou selecione um arquivo.');
        }));
    },
  },
  apk: {
    intro: 'Análise estática de APK: permissões perigosas, debuggable, tráfego HTTP, segredos hardcoded. Nada é executado.',
    render: (p) => {
      const file = fileInput('.apk', 'arquivo .apk (até 60 MB)');
      p.append(file.node,
        actions(async () => {
          if (!file.file) throw new Error('Selecione um arquivo .apk.');
          return post('/api/scan/apk', file.file);
        }));
    },
  },
};

function field(labelText, control) { return el('div', { class: 'grow' }, el('label', {}, labelText), control); }
function orSep() { return el('div', { class: 'hint' }, '— ou —'); }
function guessName(txt) {
  const t = txt.trim();
  if (t.includes('"lockfileVersion"') || t.includes('"packages"')) return 'package-lock.json';
  if (t.startsWith('{')) return 'package.json';
  return 'requirements.txt';
}
function fileInput(accept, hintText) {
  const input = el('input', { type: 'file', accept, style: 'display:none' });
  const box = el('div', { class: 'file' }, `Clique para escolher: ${hintText}`);
  const obj = { file: null, node: el('div', {}, box, input) };
  box.onclick = () => input.click();
  input.onchange = () => { if (input.files[0]) { obj.file = input.files[0]; box.textContent = `✓ ${input.files[0].name}`; } };
  return obj;
}
function actions(run) {
  const btn = el('button', { class: 'run' }, 'Analisar');
  const box = el('div', { class: 'row' }, el('div', { class: 'grow' }), btn);
  btn.onclick = async () => {
    btn.disabled = true; btn.innerHTML = '<span class="spin"></span>Analisando…';
    $('#result').innerHTML = '';
    try { renderReport(await run()); }
    catch (e) { $('#result').append(el('div', { class: 'err' }, e.message)); }
    finally { btn.disabled = false; btn.textContent = 'Analisar'; }
  };
  return box;
}

async function postJson(url, body) {
  const r = await fetch(`${API_BASE}${url}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `Erro ${r.status}`);
  return d;
}
async function post(url, file) {
  const fd = new FormData(); fd.append('file', file);
  const r = await fetch(`${API_BASE}${url}`, { method: 'POST', body: fd });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `Erro ${r.status}`);
  return d;
}

function renderReport(rep) {
  const out = $('#result');
  const { score, grade, counts, total } = rep.summary;
  const scoreColor = score >= 75 ? 'var(--acc)' : score >= 40 ? 'var(--med)' : 'var(--crit)';

  const pills = Object.entries(counts).filter(([, n]) => n > 0)
    .map(([s, n]) => el('span', { class: 'pill', style: `color:${SEV[s].c};border-color:${SEV[s].c}` }, `${SEV[s].label}: ${n}`));

  out.append(el('div', { class: 'scorebar' },
    el('div', {}, el('div', { class: 'score', style: `color:${scoreColor}` }, String(score)), el('div', { class: 'grade' }, `nota ${grade} · ${total} achado(s)`)),
    el('div', { class: 'counts' }, ...(pills.length ? pills : [el('span', { class: 'pill', style: 'color:var(--acc);border-color:var(--acc)' }, 'limpo')])),
  ));

  if (rep.meta?.notes?.length) rep.meta.notes.forEach((n) => out.append(el('div', { class: 'hint', style: 'margin:0 0 10px' }, `ℹ ${n}`)));

  if (!total) { out.append(el('div', { class: 'empty' }, '✓ Nenhum problema encontrado nas verificações executadas.')); return; }

  for (const f of rep.findings) {
    const s = SEV[f.severity];
    out.append(el('div', { class: 'f', style: `border-left-color:${s.c}` },
      el('div', { class: 'meta', style: `color:${s.c}` }, s.label),
      el('h4', {}, f.title),
      el('p', {}, f.description),
      f.evidence ? el('div', {}, el('span', { class: 'ev' }, f.evidence)) : '',
      el('p', { class: 'rec' }, '→ ', f.recommendation),
      f.reference ? el('a', { href: f.reference, target: '_blank', rel: 'noopener' }, 'Referência ↗') : '',
    ));
  }
}

function select(tab) {
  [...$('#tabs').children].forEach((b) => b.setAttribute('aria-selected', String(b.dataset.t === tab)));
  const panel = $('#panel'); panel.innerHTML = '';
  panel.append(el('p', { class: 'hint', style: 'margin:0 0 14px' }, PANELS[tab].intro));
  PANELS[tab].render(panel);
  $('#result').innerHTML = '';
}
$('#tabs').addEventListener('click', (e) => { if (e.target.dataset.t) select(e.target.dataset.t); });
select('deps');
