// Proteção contra SSRF: impede que o scanner web seja usado para sondar a rede interna
// (localhost, 10.x, 192.168.x, metadata de cloud 169.254.169.254 etc.).
import dns from 'node:dns/promises';
import net from 'node:net';

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const BLOCKED_V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([base, bits]) => [ipv4ToInt(base), bits]);

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    return BLOCKED_V4.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      return (n & mask) === (base & mask);
    });
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::1' || v === '::') return true;
    if (v.startsWith('fe80') || v.startsWith('fc') || v.startsWith('fd')) return true;
    const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return false;
  }
  return true;
}

export async function assertPublicUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw Object.assign(new Error('URL inválida.'), { statusCode: 400 });
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw Object.assign(new Error('Somente http:// e https:// são aceitos.'), { statusCode: 400 });
  }
  if (process.env.ALLOW_PRIVATE_TARGETS === 'true') return url;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((a) => a.address);
  if (addrs.some(isPrivateIp)) {
    throw Object.assign(
      new Error('Alvo resolve para endereço de rede privada/local. Para testar ambiente interno, rode localmente com ALLOW_PRIVATE_TARGETS=true.'),
      { statusCode: 400 },
    );
  }
  return url;
}
