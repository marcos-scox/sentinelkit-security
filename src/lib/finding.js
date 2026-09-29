// Formato padronizado de achado, usado por todos os módulos.
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };

export function finding({
  module, severity, title, description, evidence = null, recommendation,
  reference = null, category = 'Geral', impact = null, snippet = null,
}) {
  if (!SEVERITIES.includes(severity)) throw new Error(`Severidade inválida: ${severity}`);
  return { module, severity, category, title, description, impact, evidence, recommendation, snippet, reference };
}

// Registro de verificação aprovada — mostra ao usuário o que foi checado e passou.
export function pass(category, title, detail = null) {
  return { category, title, detail };
}

export function summarize(findings) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  // Penalidade com retorno decrescente por severidade, para muitos "low" não zerarem o score.
  let penalty = 0;
  for (const s of SEVERITIES) {
    for (let i = 0; i < counts[s]; i++) penalty += WEIGHT[s] / (1 + i * 0.5);
  }
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, counts, total: findings.length };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
}

export function report(module, target, findings, meta = {}, passed = []) {
  const sorted = sortFindings(findings);
  return {
    module, target, scannedAt: new Date().toISOString(),
    summary: { ...summarize(sorted), passed: passed.length },
    findings: sorted, passed, meta,
  };
}
