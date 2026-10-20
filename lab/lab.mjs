/*
 * Lab factory. startLab({ hardened }) boots the three-node cluster and returns
 * { ports, teardown }. Two variants from one code path:
 *
 *   hardened:false (default) — the VULNERABLE lab:
 *     A  no-auth 2-member replica set (rs-edge)   foothold + topology leak
 *     B  auth, weak default admin:admin           default-credential compromise
 *     C  auth, password that is leaked on Node A   credential-reuse pivot
 *     ...and Node A stores plaintext downstream connection strings.
 *
 *   hardened:true — the SECURE lab (same services, fixed):
 *     A  auth, strong unique creds, least-priv app user, NO stored secrets, no replset
 *     B  auth, strong unique creds (no admin:admin)
 *     C  auth, strong unique creds (not reused anywhere)
 *
 * The assessment knows none of the hardened credentials, so against the secure
 * lab it gains no access and the report goes green.
 */
import { MongoMemoryServer, MongoMemoryReplSet } from 'mongodb-memory-server-core';
import { MongoClient } from 'mongodb';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { LAB_PORTS, CREDS, NODES, seedData } from './topology.mjs';

// mongodb-memory-server puts every node's data dir under os.tmpdir().
// Four mongod data dirs total ~500 MB, which silently fills a small
// tmpfs /tmp (512 MB in one test VM) — mongod then dies mid-demo with an
// opaque fassert() failure, and a crashed run's orphan dirs make every
// later run fail too. Unless the user picked a TMPDIR themselves,
// default the data root to a project-local dir on the same disk as the
// code, where there is room. os.tmpdir() reads TMPDIR per call, so
// setting it here, before any server is created, is enough.
if (!process.env.TMPDIR) {
  const tmpRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp-lab');
  mkdirSync(tmpRoot, { recursive: true });
  process.env.TMPDIR = tmpRoot;
}

// Strong, unique, lab-only credentials for the hardened variant. None match the
// tool's default-credential list, and none are stored anywhere readable.
const HARDENED = {
  A: { root: { u: 'appadmin', p: 'Aa7$kQ2!vR9pLzEx' }, extra: [{ u: 'app_rw', p: 'Zx4!mN8@qT1wErPd', db: 'appdb', role: 'readWrite' }] },
  B: { root: { u: 'repadmin', p: 'Bb3#hJ6!xC0nMsQw' }, extra: [{ u: 'report_ro', p: 'Rr8$tV2!kP5qLwzN', db: 'reporting', role: 'read' }] },
  C: { root: { u: 'whadmin', p: 'Cc9#dF4!zX7vNqGt' }, extra: [{ u: 'etl_svc', p: 'Ee1$gH5!mB3rTyUo', db: 'warehouse', role: 'readWrite' }] },
};

const REPL_TRANSIENT = /InterruptedDueToReplStateChange|NotPrimary|PrimarySteppedDown|node is recovering/i;

async function seedDb(uri, dbName, collections) {
  // Seeding is idempotent (delete-then-insert), so it is safe to retry whole.
  // A fresh replica set can still be electing/stepping down when the first
  // write lands, which fails it with InterruptedDueToReplStateChange
  // (verified 2026-10-19: first-ever demo run crashed in seedDb on exactly
  // this). Retry transient replica-state errors with backoff instead of
  // crashing the lab startup.
  let lastErr;
  for (let attempt = 1; attempt <= 8; attempt++) {
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 20000 });
    try {
      await client.connect();
      const db = client.db(dbName);
      for (const [coll, docs] of Object.entries(collections)) {
        await db.collection(coll).deleteMany({});
        if (docs.length) await db.collection(coll).insertMany(docs);
      }
      return;
    } catch (err) {
      lastErr = err;
      if (!REPL_TRANSIENT.test(`${err.codeName || ''} ${err.message || ''}`)) throw err;
      if (attempt < 8) await new Promise((r) => setTimeout(r, 500 * attempt));
    } finally {
      try { await client.close(); } catch { /* ignore */ }
    }
  }
  throw lastErr;
}

async function standaloneAuth(port, root, extras, seedMap) {
  const srv = await MongoMemoryServer.create({
    instance: { port, ip: '127.0.0.1', auth: true },
    auth: { enable: true, customRootName: root.u, customRootPwd: root.p },
  });
  // Use the port mongod actually bound (it can differ from the request if the
  // port is briefly in TIME_WAIT), so seeding never hits a dead address.
  const u = new URL(srv.getUri());
  const uri = `mongodb://${encodeURIComponent(root.u)}:${encodeURIComponent(root.p)}@${u.hostname}:${u.port}/?authSource=admin`;
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 20000 });
  await client.connect();
  for (const e of extras) {
    try { await client.db(e.db).command({ createUser: e.u, pwd: e.p, roles: [{ role: e.role, db: e.db }] }); }
    catch (err) { if (!/already exists/i.test(err.message)) throw err; }
  }
  await client.close();
  for (const [db, colls] of Object.entries(seedMap)) await seedDb(uri, db, colls);
  return srv;
}

async function createReplSetWithRetry(opts) {
  // mongodb-memory-server waits a hard-coded 30s for a primary during
  // replSet init, with no option to raise it. On a slow or just-booted
  // machine the election can miss that window (WaitForPrimaryTimeoutError,
  // verified 2026-10-19) and the whole demo dies before it starts. Creation
  // is side-effect free until it succeeds, so retry the whole create with
  // fresh instances instead of asking the user to re-run by hand.
  let lastErr;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await MongoMemoryReplSet.create(opts);
    } catch (err) {
      lastErr = err;
      if (attempt < 3) await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  throw lastErr;
}

// mongodb-memory-server flips a node to auth-enforced slightly after it
// starts answering connections; an assessment launched inside that
// window sees an auth node as wide open and reports it wrong (observed
// 2026-10-19: an agent run seconds after lab-up reported Node C as
// "unauthenticated access" with extra criticals and missing findings).
// Gate startup on the EXPECTED auth state instead: auth nodes must
// refuse an anonymous listDatabases, the no-auth foothold must accept
// one. Poll up to ~45s; on timeout warn loudly and continue.
async function anonListsDb(port) {
  const client = new MongoClient(`mongodb://127.0.0.1:${port}/`, { serverSelectionTimeoutMS: 2500, connectTimeoutMS: 2500, directConnection: true });
  try { await client.connect(); await client.db('admin').command({ listDatabases: 1, nameOnly: true }); return true; }
  catch { return false; }
  finally { try { await client.close(); } catch { /* ignore */ } }
}
async function waitForAuthStates(expect, log) {
  const deadline = Date.now() + 45_000;
  const pending = new Map(expect); // port -> wantAnonDenied
  while (pending.size && Date.now() < deadline) {
    for (const [port, wantDenied] of [...pending]) {
      const listed = await anonListsDb(port);
      if (listed !== wantDenied) pending.delete(port);
    }
    if (pending.size) await new Promise((r) => setTimeout(r, 500));
  }
  if (pending.size) log(`WARNING: auth state not settled after 45s on port(s) ${[...pending.keys()].join(', ')} — findings may be off; re-run when the lab is warm`);
}

export async function startLab({ hardened = false, ports = null, log = () => {} } = {}) {
  const seeds = seedData({ mode: 'local' });
  const servers = [];
  const P = ports || { A: LAB_PORTS.A, A2: LAB_PORTS.A2, B: LAB_PORTS.B, C: LAB_PORTS.C };

  if (!hardened) {
    // NODE A: no-auth 2-member replica set (foothold + topology leak + secrets)
    log(`NODE A: no-auth replica set ${NODES.A.replSet} on ${P.A} + ${P.A2}`);
    const a = await createReplSetWithRetry({
      replSet: { name: NODES.A.replSet, count: 2 },
      instanceOpts: [{ port: P.A, ip: '127.0.0.1' }, { port: P.A2, ip: '127.0.0.1' }],
    });
    servers.push(a);
    for (const [db, colls] of Object.entries(seeds.A)) await seedDb(a.getUri(), db, colls);

    // NODE B: weak default admin:admin
    log(`NODE B: auth, weak default admin on ${P.B}`);
    servers.push(await standaloneAuth(P.B,
      { u: CREDS.B_admin.user, p: CREDS.B_admin.pwd },
      [{ u: CREDS.B_report.user, p: CREDS.B_report.pwd, db: 'reporting', role: 'read' }],
      seeds.B));

    // NODE C: strong-looking password that is leaked on Node A
    log(`NODE C: auth (leaked password) on ${P.C}`);
    servers.push(await standaloneAuth(P.C,
      { u: CREDS.C_admin.user, p: CREDS.C_admin.pwd },
      [{ u: CREDS.C_etl.user, p: CREDS.C_etl.pwd, db: 'warehouse', role: 'readWrite' }],
      seeds.C));
  } else {
    // Hardened A: auth, no stored secrets, no replica set.
    const aSeed = { appdb: { app_users: seeds.A.appdb.app_users, sessions: seeds.A.appdb.sessions } };
    log(`NODE A: auth, least-priv, no stored secrets on ${P.A}`);
    servers.push(await standaloneAuth(P.A, HARDENED.A.root, HARDENED.A.extra, aSeed));

    log(`NODE B: auth, strong unique creds on ${P.B}`);
    servers.push(await standaloneAuth(P.B, HARDENED.B.root, HARDENED.B.extra, seeds.B));

    log(`NODE C: auth, strong unique creds on ${P.C}`);
    servers.push(await standaloneAuth(P.C, HARDENED.C.root, HARDENED.C.extra, seeds.C));
  }

  if (!hardened) await waitForAuthStates(new Map([[P.A, false], [P.A2, false], [P.B, true], [P.C, true]]), log);
  else await waitForAuthStates(new Map([[P.A, true], [P.B, true], [P.C, true]]), log);

  async function teardown() {
    for (const s of servers.slice().reverse()) { try { await s.stop(); } catch { /* ignore */ } }
  }
  return { ports: P, teardown };
}
