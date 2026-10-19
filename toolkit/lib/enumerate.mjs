/*
 * Single-node enumeration. Everything here is READ-ONLY: hello/buildInfo,
 * listDatabases/listCollections, connectionStatus, usersInfo, and sampling a
 * few documents. No writes, no drops, no server config changes.
 */
import { MongoClient } from 'mongodb';
import { scanDocument } from './secrets.mjs';

const SAMPLE_PER_COLL = 25;
const SKIP_DBS = new Set(['admin', 'config', 'local']);

function classifyError(e) {
  const msg = String(e?.message || e);
  if (/requires authentication|not authorized|Authentication failed|command.*unauthorized/i.test(msg))
    return 'auth-required';
  if (/ECONNREFUSED|connection refused/i.test(msg)) return 'refused';
  if (/ServerSelection|timed out|ETIMEDOUT|getaddrinfo|ENOTFOUND/i.test(msg)) return 'unreachable';
  return 'error';
}

async function withClient(uri, fn) {
  const client = new MongoClient(uri, {
    serverSelectionTimeoutMS: 6000,
    connectTimeoutMS: 6000,
    directConnection: true,
  });
  try { await client.connect(); return await fn(client); }
  finally { try { await client.close(); } catch {} }
}

function buildUri(host, port, cred) {
  const auth = cred?.user
    ? `${encodeURIComponent(cred.user)}:${encodeURIComponent(cred.pass ?? '')}@`
    : '';
  const authSource = cred?.authSource || cred?.db || 'admin';
  const q = cred?.user ? `?authSource=${encodeURIComponent(authSource)}` : '';
  return `mongodb://${auth}${host}:${port}/${q}`;
}

// Pre-auth fingerprint — works even when auth is required for data commands.
export async function fingerprint(host, port) {
  try {
    return await withClient(buildUri(host, port, null), async (client) => {
      const admin = client.db('admin');
      const hello = await admin.command({ hello: 1 }).catch(() => admin.command({ isMaster: 1 }));
      let authRequired = false;
      let version = null;
      // buildInfo is allowed PRE-auth, so it is only a version source.
      try { version = (await admin.command({ buildInfo: 1 })).version; } catch { /* ignore */ }
      // listDatabases DOES require auth when access control is enabled -> use it
      // as the authentication-required signal.
      try { await admin.command({ listDatabases: 1, nameOnly: true }); }
      catch (e) { if (classifyError(e) === 'auth-required') authRequired = true; }
      return {
        reachable: true,
        version,
        authRequired,
        setName: hello.setName || null,
        members: (hello.hosts || []).concat(hello.passives || []),
        primary: hello.primary || null,
        me: hello.me || null,
        msg: hello.msg || null,
      };
    });
  } catch (e) {
    return { reachable: false, reason: classifyError(e), error: String(e.message || e) };
  }
}

// Try a list of credentials (plus anonymous) and return the first that reads
// data. `attempts` counts how many were tried before success: the learning loop
// uses it to show that proven credentials-first means fewer attempts over time.
export async function tryAccess(host, port, creds, { includeAnon = true } = {}) {
  const toTry = includeAnon ? [null, ...creds] : [...creds]; // null = anonymous
  let attempts = 0;
  for (const cred of toTry) {
    attempts++;
    try {
      const dbs = await withClient(buildUri(host, port, cred), (client) =>
        client.db('admin').command({ listDatabases: 1 }));
      return { ok: true, cred, databases: dbs.databases.map((d) => d.name), attempts };
    } catch (e) {
      const kind = classifyError(e);
      if (kind === 'refused' || kind === 'unreachable') return { ok: false, kind, attempts };
      // auth-required / error -> try next credential
    }
  }
  return { ok: false, kind: 'auth-required', attempts };
}

// Does this single credential authenticate (and read something)? Used to flag
// weak/default creds even when we already have access via a harvested one.
export async function authWorks(host, port, cred) {
  try {
    await withClient(buildUri(host, port, cred), (client) =>
      client.db('admin').command({ listDatabases: 1, nameOnly: true }));
    return true;
  } catch { return false; }
}

// Who am I, and what can I do? (privilege picture)
export async function whoAmI(host, port, cred) {
  return withClient(buildUri(host, port, cred), async (client) => {
    const admin = client.db('admin');
    const status = await admin.command({ connectionStatus: 1, showPrivileges: true }).catch(() => null);
    let users = null;
    try {
      const u = await admin.command({ usersInfo: 1 });
      users = u.users?.map((x) => ({ user: x.user, db: x.db, roles: x.roles }));
    } catch { /* not authorized to view users */ }
    return {
      authenticatedUsers: status?.authInfo?.authenticatedUsers || [],
      authenticatedUserRoles: status?.authInfo?.authenticatedUserRoles || [],
      authenticatedUserPrivileges: status?.authInfo?.authenticatedUserPrivileges || [],
      allUsers: users,
    };
  });
}

// ---- data & structure inventory -------------------------------------------
// From the same sampled documents, reconstruct what the data actually IS:
// every field path with the types seen, the indexes, and one example
// document with secret-looking values redacted. All client-side inference
// over read-only samples — no extra server commands beyond listIndexes.
const SENSITIVE_KEY_RE = /(pass(word|wd)?|pwd|pw_|_pw|bcrypt|hash|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|conn(ection)?[_-]?string|uri|dsn|credential)/i;

function bsonTypeName(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (v instanceof Date) return 'date';
  const t = typeof v;
  if (t === 'object') return v._bsontype ? String(v._bsontype).toLowerCase() : 'object';
  return t;
}

function collectFields(node, prefix, out, depth) {
  if (depth > 3 || node === null || typeof node !== 'object' || node instanceof Date || node._bsontype) return;
  if (Array.isArray(node)) {
    for (const el of node.slice(0, 5)) if (el && typeof el === 'object') collectFields(el, prefix, out, depth);
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    const path = prefix ? `${prefix}.${k}` : k;
    const tn = bsonTypeName(v);
    (out[path] ||= new Set()).add(tn);
    if (tn === 'object') collectFields(v, path, out, depth + 1);
    else if (tn === 'array') { const el = v.find((x) => x && typeof x === 'object'); if (el) collectFields(el, path, out, depth + 1); }
  }
}

function redactSample(key, v, depth) {
  if (key && SENSITIVE_KEY_RE.test(key)) return '••• redacted •••';
  if (v === null || v === undefined) return null;
  if (v instanceof Date) return v.toISOString();
  if (typeof v === 'string') return v.length > 80 ? `${v.slice(0, 80)}…` : v;
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  if (Array.isArray(v)) return depth > 2 ? `[${v.length} items]` : v.slice(0, 3).map((x) => redactSample(null, x, depth + 1));
  if (typeof v === 'object') {
    if (v._bsontype) return String(v);
    if (depth > 2) return '{…}';
    const o = {};
    for (const [k2, v2] of Object.entries(v).slice(0, 20)) o[k2] = redactSample(k2, v2, depth + 1);
    return o;
  }
  return String(v);
}

// Enumerate databases -> collections -> sample docs; harvest secrets/URIs.
// `collRank` (name -> score) orders collections so names that historically held
// secrets are sampled first, which surfaces pivot material sooner.
export async function harvest(host, port, cred, databases, collRank = null) {
  return withClient(buildUri(host, port, cred), async (client) => {
    const result = { databases: {}, uris: new Set(), secrets: [] };
    for (const dbName of databases) {
      if (SKIP_DBS.has(dbName)) continue;
      const db = client.db(dbName);
      let colls;
      try { colls = await db.listCollections().toArray(); }
      catch { continue; }
      if (collRank) colls.sort((a, b) => (collRank[b.name] || 0) - (collRank[a.name] || 0));
      result.databases[dbName] = {};
      for (const c of colls) {
        const coll = db.collection(c.name);
        let count = 0, docs = [], indexes = [];
        try {
          count = await coll.estimatedDocumentCount();
          docs = await coll.find({}, { limit: SAMPLE_PER_COLL }).toArray();
        } catch { /* unreadable collection */ }
        try { indexes = (await coll.indexes()).map((ix) => ({ name: ix.name, keys: ix.key })); } catch { /* indexes need no extra privilege in practice; best effort */ }
        const fieldMap = {};
        for (const d of docs) collectFields(d, '', fieldMap, 0);
        const fields = {};
        for (const [k, set] of Object.entries(fieldMap)) fields[k] = [...set].sort();
        result.databases[dbName][c.name] = {
          count, sampled: docs.length,
          fields, indexes,
          sample: docs.length ? redactSample(null, docs[0], 0) : null,
        };
        for (const doc of docs) {
          const { uris, keyedSecrets } = scanDocument(doc, { source: `${host}:${port}/${dbName}.${c.name}` });
          uris.forEach((u) => result.uris.add(u));
          for (const s of keyedSecrets) result.secrets.push(s);
        }
      }
    }
    result.uris = [...result.uris];
    return result;
  });
}
