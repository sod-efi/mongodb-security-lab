/*
 * Target-scope guardrails. This assessment tool is for a lab you own.
 * By default it will ONLY talk to loopback and RFC1918 private addresses, plus
 * the Docker lab service hostnames. Anything else is refused unless the
 * operator explicitly passes --authorized-external (use only with written
 * authorization for the target you own/are engaged to test).
 */
const LAB_HOSTNAMES = new Set([
  'localhost', 'node-a-appdb', 'node-b-reporting', 'node-c-warehouse',
]);

function isPrivateIPv4(h) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 127) return true;                 // loopback
  if (a === 10) return true;                  // 10.0.0.0/8
  if (a === 192 && b === 168) return true;    // 192.168.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 169 && b === 254) return true;    // link-local
  return false;
}

export function isInScope(host, { allowExternal = false } = {}) {
  if (allowExternal) return true;
  const h = String(host).toLowerCase();
  if (h === '::1') return true;
  if (LAB_HOSTNAMES.has(h)) return true;
  return isPrivateIPv4(h);
}

export function assertInScope(host, opts) {
  if (!isInScope(host, opts)) {
    throw new Error(
      `REFUSED: ${host} is not a lab/private target. This tool is scoped to a lab ` +
      `you control. Re-run with --authorized-external only if you have written ` +
      `authorization to test that host.`);
  }
}

export function banner() {
  return [
    '────────────────────────────────────────────────────────────',
    ' MongoDB cluster assessment  —  AUTHORIZED LAB USE ONLY',
    ' Read-only recon + pivot. Point it only at systems you own or',
    ' are explicitly authorized to test.',
    '────────────────────────────────────────────────────────────',
  ].join('\n');
}
