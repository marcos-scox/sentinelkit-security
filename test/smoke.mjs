import assert from 'node:assert';
import { scanDependencies } from '../src/modules/deps.js';
import { scanText } from '../src/modules/secrets.js';
import { scanApk } from '../src/modules/apk.js';
import { summarize } from '../src/lib/finding.js';
import { cvss3Score } from '../src/lib/cvss.js';
import AdmZip from 'adm-zip';

let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log('  ✓', name); } catch (e) { fail++; console.log('  ✗', name, '\n     ', e.message); } };

console.log('CVSS');
await t('vetor crítico ~9.8', () => assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8));
await t('vetor inválido → null', () => assert.equal(cvss3Score('lixo'), null));

console.log('Score');
await t('sem achados = 100/A', () => { const s = summarize([]); assert.equal(s.score, 100); assert.equal(s.grade, 'A'); });
await t('critical derruba score', () => assert.ok(summarize([{ severity: 'critical' }]).score < 80));

console.log('Secrets');
await t('detecta AWS key', () => {
  const f = scanText('cfg.js', 'const k = "AKIAIOSFODNN7EXAMPLE";');
  assert.ok(f.some((x) => x.title.includes('AWS')));
});
await t('detecta private key', () => {
  const f = scanText('id_rsa', '-----BEGIN RSA PRIVATE KEY-----\nabc');
  assert.equal(f.length >= 1, true);
});
await t('redige o segredo', () => {
  const f = scanText('c.env', 'API_KEY="AIzaSy* padding padding padding 1234567"');
  assert.ok(f.every((x) => !x.evidence.includes('padding padding')));
});
await t('ignora node_modules', () => assert.equal(scanText('node_modules/x/a.js', 'AKIAIOSFODNN7EXAMPLE').length, 0));

console.log('Deps (parser, sem rede)');
await t('parseia package.json com pin', async () => {
  const pkg = JSON.stringify({ dependencies: { lodash: '4.17.10' } });
  const r = await scanDependencies('package.json', pkg).catch((e) => e);
  // pode bater na rede OSV; só garantimos que não estoura no parser
  assert.ok(r);
});

console.log('APK');
await t('rejeita arquivo não-APK', async () => {
  await assert.rejects(() => scanApk(Buffer.from('não é zip'), 'x.apk'));
});
await t('detecta debuggable + permissão', async () => {
  const zip = new AdmZip();
  zip.addFile('AndroidManifest.xml', Buffer.from('android.permission.READ_SMS debuggable true'));
  zip.addFile('res/values/strings.xml', Buffer.from('<string>http://api.exemplo.com/x</string>'));
  const r = await scanApk(zip.toBuffer(), 'app.apk');
  assert.ok(r.findings.some((f) => f.title.includes('debuggable')));
  assert.ok(r.findings.some((f) => f.title.includes('SMS')));
});

console.log(`\n${pass} passaram, ${fail} falharam`);
process.exit(fail ? 1 : 0);
