/*
 * Secret harvesting helpers.
 *
 * A very common way one compromised MongoDB node leads to others: applications
 * store downstream connection strings / API keys inside the database itself.
 * These helpers (a) find mongodb:// URIs and other secret-looking values in
 * arbitrary documents, and (b) parse a mongodb URI into a reusable credential +
 * target so the pivot engine can try it against the next node.
 */

const URI_RE = /mongodb(?:\+srv)?:\/\/[^\s"'`]+/gi;

// Field names that commonly hold secrets, matched case-insensitively.
const SECRET_KEY_RE = /(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|conn(ection)?[_-]?string|uri|dsn|credential)/i;

export function parseMongoUri(uri) {
  // mongodb://user:pass@host1:port1,host2:port2/db?opts
  const m = /^mongodb(?:\+srv)?:\/\/(?:([^:@/]+)(?::([^@/]*))?@)?([^/?]+)(?:\/([^?]*))?(?:\?(.*))?$/i.exec(uri);
  if (!m) return null;
  const [, user, pass, hostpart, db, query] = m;
  const hosts = hostpart.split(',').map((hp) => {
    const [host, port] = hp.split(':');
    return { host, port: port ? Number(port) : 27017 };
  });
  const opts = Object.fromEntries(
    (query || '').split('&').filter(Boolean).map((kv) => {
      const [k, v] = kv.split('=');
      return [k, decodeURIComponent(v ?? '')];
    }));
  return {
    raw: uri,
    user: user ? decodeURIComponent(user) : null,
    pass: pass != null ? decodeURIComponent(pass) : null,
    hosts,
    db: db || null,
    authSource: opts.authSource || null,
    replicaSet: opts.replicaSet || null,
  };
}

// Walk a document recursively and collect findings.
export function scanDocument(doc, { source } = {}) {
  const uris = new Set();
  const keyedSecrets = [];
  (function walk(node, path) {
    if (node == null) return;
    if (typeof node === 'string') {
      let mm;
      URI_RE.lastIndex = 0;
      while ((mm = URI_RE.exec(node))) uris.add(mm[0]);
      return;
    }
    if (Array.isArray(node)) { node.forEach((v, i) => walk(v, `${path}[${i}]`)); return; }
    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if (typeof v === 'string' && SECRET_KEY_RE.test(k)) {
          keyedSecrets.push({ field: `${path}${path ? '.' : ''}${k}`, value: v, source });
        }
        walk(v, `${path}${path ? '.' : ''}${k}`);
      }
    }
  })(doc, '');
  return { uris: [...uris], keyedSecrets };
}
