// Módulo 4 — Análise estática de APK. Só LÊ o conteúdo do pacote; nada é executado.
import AdmZip from 'adm-zip';
import { finding, report } from '../lib/finding.js';
import { scanText } from './secrets.js';

const MODULE = 'apk';

// Permissões consideradas perigosas/sensíveis (subconjunto prático da doc Android).
const DANGEROUS_PERMS = {
  'android.permission.READ_SMS': 'high',
  'android.permission.SEND_SMS': 'high',
  'android.permission.RECEIVE_SMS': 'high',
  'android.permission.READ_CONTACTS': 'medium',
  'android.permission.ACCESS_FINE_LOCATION': 'medium',
  'android.permission.ACCESS_BACKGROUND_LOCATION': 'high',
  'android.permission.RECORD_AUDIO': 'high',
  'android.permission.CAMERA': 'medium',
  'android.permission.READ_CALL_LOG': 'high',
  'android.permission.READ_EXTERNAL_STORAGE': 'low',
  'android.permission.WRITE_EXTERNAL_STORAGE': 'medium',
  'android.permission.REQUEST_INSTALL_PACKAGES': 'high',
  'android.permission.SYSTEM_ALERT_WINDOW': 'medium',
  'android.permission.QUERY_ALL_PACKAGES': 'medium',
  'android.permission.READ_PHONE_STATE': 'medium',
};

// Extrai strings legíveis de um buffer binário (AndroidManifest é binário no APK).
function strings(buf, min = 6) {
  const out = [];
  let cur = '';
  for (const b of buf) {
    if (b >= 32 && b < 127) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= min) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= min) out.push(cur);
  return out;
}

export async function scanApk(buffer, filename = 'app.apk') {
  let zip;
  try {
    zip = new AdmZip(buffer);
  } catch {
    throw Object.assign(new Error('Arquivo não é um APK/ZIP válido.'), { statusCode: 400 });
  }
  const entries = zip.getEntries();
  const findings = [];

  const manifestEntry = entries.find((e) => e.entryName === 'AndroidManifest.xml');
  if (!manifestEntry) {
    throw Object.assign(new Error('AndroidManifest.xml não encontrado — o arquivo é mesmo um APK?'), { statusCode: 400 });
  }
  const manifestStr = strings(manifestEntry.getData(), 4);
  const manifestJoined = manifestStr.join('\n');

  // 1) Permissões perigosas
  const foundPerms = manifestJoined.match(/android\.permission\.[A-Z_]+/g) || [];
  for (const perm of new Set(foundPerms)) {
    const sev = DANGEROUS_PERMS[perm];
    if (sev) {
      findings.push(finding({
        module: MODULE, severity: sev, title: `Permissão sensível: ${perm.split('.').pop()}`,
        description: `O app declara ${perm}.`,
        recommendation: 'Confirme se a funcionalidade realmente exige esta permissão; remova se não usar.',
      }));
    }
  }

  // 2) Flags de configuração no manifest
  if (/debuggable/i.test(manifestJoined)) {
    findings.push(finding({
      module: MODULE, severity: 'high', title: 'App possivelmente marcado como debuggable',
      description: 'android:debuggable="true" em produção permite inspecionar e manipular o app.',
      recommendation: 'Garanta android:debuggable="false" na build de release.',
    }));
  }
  if (/usesCleartextTraffic|cleartextTrafficPermitted/i.test(manifestJoined)) {
    findings.push(finding({
      module: MODULE, severity: 'medium', title: 'Tráfego em texto claro permitido',
      description: 'A configuração permite HTTP não criptografado, sujeito a interceptação.',
      recommendation: 'Defina usesCleartextTraffic="false" e use HTTPS + Network Security Config.',
    }));
  }
  if (/allowBackup/i.test(manifestJoined) && !/allowBackup.{0,20}false/i.test(manifestJoined)) {
    findings.push(finding({
      module: MODULE, severity: 'low', title: 'Backup do app habilitado (allowBackup)',
      description: 'Permite extrair dados do app via adb backup em dispositivos vulneráveis.',
      recommendation: 'Defina android:allowBackup="false" se o app manipula dados sensíveis.',
    }));
  }

  // 3) Segredos hardcoded em arquivos de código/config e URLs http://
  const CODE = /\.(smali|xml|json|properties|js|txt|kt|java|cfg|ini|gradle)$/i;
  let cleartextUrls = 0;
  let scanned = 0;
  for (const e of entries) {
    if (e.isDirectory) continue;
    if (e.entryName === 'AndroidManifest.xml') continue;
    if (!CODE.test(e.entryName) && !e.entryName.includes('strings')) continue;
    if (e.header.size > 500_000) continue;
    let text;
    try { text = e.getData().toString('utf8'); } catch { continue; }
    scanned++;
    findings.push(...scanText(`apk:${e.entryName}`, text).map((f) => ({ ...f, module: MODULE })));
    const httpMatches = text.match(/http:\/\/(?!localhost|127\.|schemas\.android|www\.w3\.org)[^\s"'<>]+/g);
    if (httpMatches) cleartextUrls += httpMatches.length;
  }
  if (cleartextUrls > 0) {
    findings.push(finding({
      module: MODULE, severity: 'low', title: `${cleartextUrls} URL(s) HTTP em texto claro no código`,
      description: 'Endpoints http:// podem expor dados a interceptação de rede.',
      recommendation: 'Migre todas as chamadas para https://.',
    }));
  }

  // 4) Assinatura
  const hasV2 = entries.some((e) => e.entryName === 'META-INF/CERT.SF' || /META-INF\/.*\.(RSA|DSA|EC)$/.test(e.entryName));
  if (!hasV2) {
    findings.push(finding({
      module: MODULE, severity: 'info', title: 'Assinatura não detectada nos metadados',
      description: 'Não foi encontrado bloco de assinatura clássico (pode usar apenas v2/v3 no bloco APK Signing).',
      recommendation: 'Confirme a assinatura com apksigner verify.',
    }));
  }

  return report(MODULE, filename, findings, {
    entries: entries.length, permissions: [...new Set(foundPerms)].length, filesScanned: scanned,
  });
}
