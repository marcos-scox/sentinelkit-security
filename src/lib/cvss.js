// Cálculo do score base CVSS v3.x a partir do vetor (ex.: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

const roundUp = (x) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

export function cvss3Score(vector) {
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3')) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  const S = m.S;
  try {
    const iss = 1 - (1 - W.C[m.C]) * (1 - W.I[m.I]) * (1 - W.A[m.A]);
    const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
    const expl = 8.22 * W.AV[m.AV] * W.AC[m.AC] * PR[S][m.PR] * W.UI[m.UI];
    if (![iss, impact, expl].every(Number.isFinite)) return null;
    if (impact <= 0) return 0;
    return S === 'U' ? roundUp(Math.min(impact + expl, 10)) : roundUp(Math.min(1.08 * (impact + expl), 10));
  } catch {
    return null;
  }
}

export function scoreToSeverity(score) {
  if (score == null) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
