/*
 * Lab-subnet discovery: a plain TCP connect-scan (no raw sockets, no nmap) that
 * finds listening MongoDB-range ports so the assessment can locate its own seed
 * nodes instead of being handed one.
 *
 * Scope-guarded: every host is checked against safety.isInScope before any
 * connection, and the host count is capped so this cannot become a mass scan.
 */
import net from 'node:net';
import { isInScope } from './safety.mjs';

const MAX_HOSTS = 256;        // refuse anything bigger than a /24
const DEFAULT_PORTS = [27017, 27018, 27019, 27020, 27021];

// "27017-27021" | "27017,27019" | "27017" -> [27017, ...]
export function parsePorts(spec) {
  if (!spec) return DEFAULT_PORTS;
  const out = new Set();
  for (const part of String(spec).split(',')) {
    const m = /^(\d+)-(\d+)$/.exec(part.trim());
    if (m) { for (let p = +m[1]; p <= +m[2]; p++) out.add(p); }
    else if (/^\d+$/.test(part.trim())) out.add(+part.trim());
  }
  return [...out].filter((p) => p > 0 && p < 65536);
}

// "127.0.0.1" | "10.0.0.0/28" | "localhost" -> [host, ...]
export function expandTargets(spec) {
  const s = String(spec).trim();
  const cidr = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(s);
  if (!cidr) return [s]; // single IP or hostname
  const bits = +cidr[5];
  if (bits < 24 || bits > 32) throw new Error(`REFUSED: CIDR /${bits} too large — use /24../32 for a lab sweep.`);
  const base = (((+cidr[1]) << 24) | ((+cidr[2]) << 16) | ((+cidr[3]) << 8) | (+cidr[4])) >>> 0;
  const count = 2 ** (32 - bits);
  if (count > MAX_HOSTS) throw new Error(`REFUSED: ${count} hosts exceeds the ${MAX_HOSTS}-host cap.`);
  const start = base & (~((count - 1)) >>> 0);
  const hosts = [];
  for (let i = 0; i < count; i++) {
    const ip = (start + i) >>> 0;
    hosts.push(`${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}`);
  }
  return hosts;
}

function tcpOpen(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (v) => { if (!done) { done = true; sock.destroy(); resolve(v); } };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('timeout', () => finish(false));
    sock.once('error', () => finish(false));
    sock.connect(port, host);
  });
}

// Simple bounded-concurrency sweep. Returns ["host:port", ...] for open ports.
export async function sweep(spec, portSpec, { allowExternal = false, concurrency = 64, timeoutMs = 800, onOpen } = {}) {
  const hosts = expandTargets(spec);
  const ports = parsePorts(portSpec);
  const inScope = hosts.filter((h) => isInScope(h, { allowExternal }));
  const refused = hosts.length - inScope.length;
  if (!inScope.length) {
    throw new Error(`REFUSED: no in-scope hosts in "${spec}". This tool sweeps lab/private targets only (use --authorized-external only with written authorization).`);
  }

  const jobs = [];
  for (const h of inScope) for (const p of ports) jobs.push([h, p]);

  const open = [];
  let idx = 0;
  async function worker() {
    while (idx < jobs.length) {
      const [h, p] = jobs[idx++];
      if (await tcpOpen(h, p, timeoutMs)) { const id = `${h}:${p}`; open.push(id); onOpen?.(id); }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, jobs.length) }, worker));
  return { open, scanned: jobs.length, hosts: inScope.length, ports: ports.length, refused };
}
