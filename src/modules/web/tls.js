// Certificado e protocolo TLS: validade, emissor, hostname, versões legadas aceitas.
import tls from 'node:tls';
import { finding, pass } from '../../lib/finding.js';

const CAT = 'TLS / Certificado';

function connect(host, port, extra = {}) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: 8000, ...extra }, () => {
      const info = {
        authorized: sock.authorized,
        authError: sock.authorizationError ? String(sock.authorizationError) : null,
        protocol: sock.getProtocol(),
        cipher: sock.getCipher()?.name,
        cert: sock.getPeerCertificate(false),
      };
      sock.end();
      resolve(info);
    });
    sock.on('timeout', () => { sock.destroy(); reject(new Error('timeout')); });
    sock.on('error', reject);
  });
}

async function acceptsLegacy(host, port) {
  try {
    await connect(host, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0' });
    return true;
  } catch { return false; }
}

export async function checkTls(url, M) {
  const findings = [];
  const passed = [];
  if (url.protocol !== 'https:') {
    findings.push(finding({
      module: M, severity: 'high', category: CAT, title: 'Site servido sem HTTPS',
      description: 'A URL analisada usa http://. Todo o tráfego, incluindo logins e dados, trafega sem criptografia.',
      impact: 'Qualquer pessoa na mesma rede (Wi-Fi público, provedor) pode ler e alterar o conteúdo.',
      recommendation: 'Ative HTTPS (Let\'s Encrypt é gratuito) e redirecione todo o HTTP para HTTPS.',
    }));
    return { findings, passed, info: null };
  }

  const host = url.hostname;
  const port = Number(url.port) || 443;
  let info;
  try {
    info = await connect(host, port);
  } catch (e) {
    findings.push(finding({
      module: M, severity: 'medium', category: CAT, title: 'Não foi possível negociar TLS',
      description: `Falha na conexão TLS: ${e.message}.`, recommendation: 'Verifique a configuração TLS do servidor.',
    }));
    return { findings, passed, info: null };
  }

  const c = info.cert || {};
  const validTo = c.valid_to ? new Date(c.valid_to) : null;
  const daysLeft = validTo ? Math.floor((validTo - Date.now()) / 86400000) : null;
  const issuer = c.issuer?.O || c.issuer?.CN || null;

  if (daysLeft != null) {
    if (daysLeft < 0) {
      findings.push(finding({ module: M, severity: 'critical', category: CAT, title: 'Certificado expirado',
        description: `O certificado expirou em ${validTo.toLocaleDateString('pt-BR')}.`,
        impact: 'Navegadores exibem alerta de segurança e usuários ficam expostos a interceptação.',
        recommendation: 'Renove o certificado imediatamente e automatize a renovação.' }));
    } else if (daysLeft < 15) {
      findings.push(finding({ module: M, severity: 'high', category: CAT, title: `Certificado expira em ${daysLeft} dia(s)`,
        description: `Validade até ${validTo.toLocaleDateString('pt-BR')}.`,
        recommendation: 'Renove agora e confirme que a renovação automática está funcionando.' }));
    } else if (daysLeft < 21) {
      findings.push(finding({ module: M, severity: 'info', category: CAT, title: `Certificado expira em ${daysLeft} dias`,
        description: `Validade até ${validTo.toLocaleDateString('pt-BR')}.`,
        recommendation: 'Confirme que a renovação automática está ativa.' }));
    } else {
      passed.push(pass(CAT, 'Certificado válido', `${daysLeft} dias restantes · emitido por ${issuer || 'desconhecido'}`));
    }
  }

  if (!info.authorized) {
    findings.push(finding({ module: M, severity: 'high', category: CAT, title: 'Certificado não confiável',
      description: `O navegador não validaria este certificado (${info.authError}).`,
      impact: 'Pode indicar certificado autoassinado, cadeia incompleta ou nome de domínio incorreto.',
      recommendation: 'Use um certificado de uma CA pública e envie a cadeia intermediária completa.' }));
  } else {
    passed.push(pass(CAT, 'Cadeia de certificado confiável', info.authError || 'validada pelas CAs do sistema'));
  }

  if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(info.protocol)) {
    findings.push(finding({ module: M, severity: 'high', category: CAT, title: `Protocolo obsoleto negociado: ${info.protocol}`,
      description: 'O servidor escolheu um protocolo descontinuado.', recommendation: 'Habilite apenas TLS 1.2 e 1.3.' }));
  } else {
    passed.push(pass(CAT, `Protocolo moderno (${info.protocol})`, info.cipher));
  }

  if (await acceptsLegacy(host, port)) {
    findings.push(finding({ module: M, severity: 'medium', category: CAT, title: 'Servidor ainda aceita TLS 1.0/1.1',
      description: 'Clientes antigos conseguem negociar versões de TLS com fraquezas conhecidas (BEAST, POODLE-TLS).',
      recommendation: 'Desative TLS 1.0 e 1.1 na configuração do servidor ou CDN.',
      reference: 'https://datatracker.ietf.org/doc/rfc8996/' }));
  } else {
    passed.push(pass(CAT, 'TLS 1.0/1.1 recusados'));
  }

  return {
    findings, passed,
    info: {
      protocol: info.protocol, cipher: info.cipher, issuer,
      subject: c.subject?.CN || null,
      validFrom: c.valid_from || null, validTo: c.valid_to || null, daysLeft,
      san: c.subjectaltname ? c.subjectaltname.split(', ').slice(0, 8).map((s) => s.replace('DNS:', '')) : [],
    },
  };
}
