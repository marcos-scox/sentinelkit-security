// Módulo 1 — Dependências vulneráveis.
// Lê manifestos/lockfiles e consulta a base pública OSV.dev (https://osv.dev).
import { finding, report } from '../lib/finding.js';
import { cvss3Score, scoreToSeverity } from '../lib/cvss.js';

const OSV = 'https://api.osv.dev/v1';
const MODULE = 'deps';

// ---------- Parsers ----------
function cleanNpmVersion(spec) {
  if (typeof spec !== 'string') return null;
  if (/^(file:|link:|git|github:|http|workspace:|npm:)/.test(spec) || spec.includes('/')) return null;
  const m = spec.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
}

export function parseManifest(filename, content) {
  const name = filename.toLowerCase().split(/[\\/]/).pop();
  const pkgs = [];
  const notes = [];

  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
    const lock = JSON.parse(content);
    if (lock.packages) {
      for (const [path, info] of Object.entries(lock.packages)) {
        if (!path || !info.version) continue;
        const pkgName = info.name || path.split('node_modules/').pop();
        pkgs.push({ name: pkgName, version: info.version, ecosystem: 'npm', dev: !!info.dev });
      }
    } else if (lock.dependencies) {
      const walk = (deps) => {
        for (const [n, info] of Object.entries(deps)) {
          if (info.version) pkgs.push({ name: n, version: info.version, ecosystem: 'npm', dev: !!info.dev });
          if (info.dependencies) walk(info.dependencies);
        }
      };
      walk(lock.dependencies);
    }
    return { pkgs: dedupe(pkgs), notes, exact: true };
  }

  if (name === 'package.json') {
    const pkg = JSON.parse(content);
    for (const [field, dev] of [['dependencies', false], ['devDependencies', true], ['optionalDependencies', false]]) {
      for (const [n, spec] of Object.entries(pkg[field] || {})) {
        const v = cleanNpmVersion(spec);
        if (v) pkgs.push({ name: n, version: v, ecosystem: 'npm', dev });
        else notes.push(`Ignorado ${n}@${spec} (versão não resolvível).`);
      }
    }
    notes.push('package.json só tem faixas de versão (ex.: ^1.2.0). Envie o package-lock.json para resultado exato.');
    return { pkgs: dedupe(pkgs), notes, exact: false };
  }

  if (name.endsWith('.txt') && name.includes('requirements')) {
    const unpinned = [];
    for (let line of content.split(/\r?\n/)) {
      line = line.split('#')[0].trim();
      if (!line || line.startsWith('-')) continue;
      const m = line.match(/^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.!+\-]+)/);
      if (m) pkgs.push({ name: m[1], version: m[2], ecosystem: 'PyPI', dev: false });
      else unpinned.push(line.split(/[<>=~!;\s]/)[0]);
    }
    return { pkgs: dedupe(pkgs), notes, exact: true, unpinned };
  }

  throw Object.assign(
    new Error('Formato não suportado. Envie package-lock.json, package.json ou requirements.txt.'),
    { statusCode: 400 },
  );
}

function dedupe(pkgs) {
  const seen = new Map();
  for (const p of pkgs) seen.set(`${p.ecosystem}:${p.name}@${p.version}`, p);
  return [...seen.values()];
}

// ---------- OSV ----------
async function osvFetch(path, body) {
  const res = await fetch(`${OSV}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) throw new Error(`OSV respondeu ${res.status} em ${path}`);
  return res.json();
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]).catch(() => null);
    }
  });
  await Promise.all(workers);
  return out;
}

function severityOf(vuln) {
  const db = vuln.database_specific?.severity?.toUpperCase();
  const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
  if (db && map[db]) return { severity: map[db], cvss: null };
  const vec = (vuln.severity || []).find((s) => s.type?.startsWith('CVSS_V3'))?.score;
  const score = cvss3Score(vec);
  return { severity: scoreToSeverity(score) || 'medium', cvss: score };
}

function fixedVersions(vuln, pkgName) {
  const fixed = new Set();
  for (const a of vuln.affected || []) {
    if (a.package?.name?.toLowerCase() !== pkgName.toLowerCase()) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed];
}

export async function scanDependencies(filename, content) {
  const { pkgs, notes, exact, unpinned = [] } = parseManifest(filename, content);
  const findings = [];

  if (unpinned.length) {
    findings.push(finding({
      module: MODULE, severity: 'low',
      title: `${unpinned.length} dependência(s) Python sem versão fixa`,
      description: 'Pacotes sem "==" podem instalar versões diferentes a cada build, inclusive vulneráveis.',
      evidence: unpinned.slice(0, 20).join(', '),
      recommendation: 'Fixe versões (pip freeze > requirements.txt) ou use pip-tools/poetry com lockfile.',
    }));
  }

  if (!pkgs.length) return report(MODULE, filename, findings, { packages: 0, notes });

  const BATCH = 500;
  const hits = []; // { pkg, ids }
  for (let i = 0; i < pkgs.length; i += BATCH) {
    const slice = pkgs.slice(i, i + BATCH);
    const data = await osvFetch('/querybatch', {
      queries: slice.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
    });
    data.results.forEach((r, j) => {
      if (r.vulns?.length) hits.push({ pkg: slice[j], ids: r.vulns.map((v) => v.id) });
    });
  }

  const uniqueIds = [...new Set(hits.flatMap((h) => h.ids))].slice(0, 400);
  const details = await mapLimit(uniqueIds, 8, (id) => osvFetch(`/vulns/${encodeURIComponent(id)}`));
  const byId = new Map(uniqueIds.map((id, k) => [id, details[k]]));

  for (const { pkg, ids } of hits) {
    for (const id of ids) {
      const v = byId.get(id);
      // OSV costuma ter o mesmo problema como GHSA e PYSEC/CVE; mantém um só por pacote.
      const { severity, cvss } = v ? severityOf(v) : { severity: 'medium', cvss: null };
      const fixed = v ? fixedVersions(v, pkg.name) : [];
      const cve = v?.aliases?.find((a) => a.startsWith('CVE-'));
      const f = finding({
        module: MODULE, severity,
        title: `${pkg.name}@${pkg.version}: ${v?.summary || id}`,
        description: [
          `${id}${cve ? ` / ${cve}` : ''}${cvss != null ? ` — CVSS ${cvss}` : ''}.`,
          pkg.dev ? 'Dependência de desenvolvimento (risco menor em produção).' : '',
        ].filter(Boolean).join(' '),
        evidence: `${pkg.ecosystem} ${pkg.name}@${pkg.version}`,
        recommendation: fixed.length
          ? `Atualize para ${fixed.join(' ou ')} (ou superior).`
          : 'Sem versão corrigida publicada. Avalie substituir o pacote ou mitigar o uso.',
        reference: `https://osv.dev/vulnerability/${id}`,
      });
      f._key = `${pkg.name}|${[id, ...(v?.aliases || [])].sort()[0]}`;
      findings.push(f);
    }
  }

  // Remove duplicatas por alias.
  const seen = new Set();
  const unique = findings.filter((f) => {
    const k = f._key;
    delete f._key;
    if (!k) return true;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return report(MODULE, filename, unique, {
    packages: pkgs.length,
    vulnerablePackages: hits.length,
    exactVersions: exact,
    notes,
  });
}
