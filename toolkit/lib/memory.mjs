/*
 * Self-improvement memory.
 *
 * The assessment gets better with use: after each run it records which
 * credentials authenticated, which ports hosted a node, and which collection
 * names held secrets. The next run reads this back and tries the proven ones
 * FIRST, so it reaches the same result with fewer authentication attempts and
 * less time. Everything is bounded, local, and resettable.
 *
 * The store is lab/local only (it may contain lab credentials) and is
 * git-ignored. Reset wipes it (keeping one .bak for undo).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';

const empty = () => ({
  version: 2,
  creds: {},              // global: credKey -> {user,pass,authSource,hits}
  portCreds: {},          // port -> { credKey -> {...,hits} }  (proven per node)
  portDefaultProbed: {},  // port -> true once the default list was fully probed
  ports: {},              // port -> reachable count
  secretCollections: {},  // collection name -> secret-hit count
  runs: [],
});

export const credKey = (c) => `${c.user}:${c.pass == null ? '' : c.pass}@${c.authSource || 'admin'}`;

export function loadKnowledge(path) {
  try { return { ...empty(), ...JSON.parse(readFileSync(path, 'utf8')) }; }
  catch { return empty(); }
}

export function saveKnowledge(path, k) {
  mkdirSync(dirname(path), { recursive: true });
  if (existsSync(path)) { try { copyFileSync(path, path + '.bak'); } catch { /* ignore */ } }
  writeFileSync(path, JSON.stringify(k, null, 2));
}

export function resetKnowledge(path) {
  try { if (existsSync(path)) { copyFileSync(path, path + '.bak'); rmSync(path); } } catch { /* ignore */ }
}

// ---- ranking (applied at the start of a run) -----------------------------
// Proven credentials, most-successful first.
export function learnedCreds(k) {
  return Object.values(k.creds)
    .sort((a, b) => b.hits - a.hits)
    .map((c) => ({ user: c.user, pass: c.pass, authSource: c.authSource }));
}
// Sort a list of "host:port" discovery hits so proven ports come first.
export function rankOpenPorts(k, openIds) {
  return openIds.slice().sort((a, b) => (k.ports[b.split(':')[1]] || 0) - (k.ports[a.split(':')[1]] || 0));
}
// Sort default-cred list so historically-successful defaults are tried first.
export function rankDefaults(k, defaults) {
  return defaults.slice().sort((a, b) => (k.creds[credKey(b)]?.hits || 0) - (k.creds[credKey(a)]?.hits || 0));
}

// Proven credentials for a specific port, best first.
export function provenCredsForPort(k, port) {
  return Object.values(k.portCreds[port] || {})
    .sort((a, b) => b.hits - a.hits)
    .map((c) => ({ user: c.user, pass: c.pass, authSource: c.authSource }));
}
// A default-list credential that previously worked on this port (so we can try
// just that one instead of the whole list).
export function provenDefaultForPort(k, port, defaults) {
  const pc = k.portCreds[port] || {};
  return defaults.find((d) => pc[credKey(d)]) || null;
}
export const defaultsProbed = (k, port) => Boolean(k.portDefaultProbed[port]);

// ---- recording (during a run) --------------------------------------------
export function recordCred(k, c) {
  const key = credKey(c);
  k.creds[key] = k.creds[key] || { user: c.user, pass: c.pass, authSource: c.authSource || 'admin', hits: 0 };
  k.creds[key].hits++;
}
export function recordPortCred(k, port, c) {
  k.portCreds[port] = k.portCreds[port] || {};
  const key = credKey(c);
  k.portCreds[port][key] = k.portCreds[port][key] || { user: c.user, pass: c.pass, authSource: c.authSource || 'admin', hits: 0 };
  k.portCreds[port][key].hits++;
}
export function markDefaultsProbed(k, port) { k.portDefaultProbed[port] = true; }
export function recordPort(k, port) { k.ports[port] = (k.ports[port] || 0) + 1; }
export function recordColl(k, name) { k.secretCollections[name] = (k.secretCollections[name] || 0) + 1; }
