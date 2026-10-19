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
import { LAB_PORTS, CREDS, NODES, seedData } from './topology.mjs';

// Strong, unique, lab-only credentials for the hardened variant. None match the
// tool's default-credential list, and none are stored anywhere readable.
const HARDENED = {
  A: { root: { u: 'appadmin', p: 'Aa7$kQ2!vR9pLzEx' }, extra: [{ u: 'app_rw', p: 'Zx4!mN8@qT1wErPd', db: 'appdb', role: 'readWrite' }] },
  B: { root: { u: 'repadmin', p: 'Bb3#hJ6!xC0nMsQw' }, extra: [{ u: 'report_ro', p: 'Rr8$tV2!kP5qLwzN', db: 'reporting', role: 'read' }] },
  C: { root: { u: 'whadmin', p: 'Cc9#dF4!zX7vNqGt' }, extra: [{ u: 'etl_svc', p: 'Ee1$gH5!mB3rTyUo', db: 'warehouse', role: 'readWrite' }] },
};

async function seedDb(uri, dbName, collections) {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 20000 });
  await client.connect();
  const db = client.db(dbName);
  for (const [coll, docs] of Object.entries(collections)) {
    await db.collection(coll).deleteMany({});
    if (docs.length) await db.collection(coll).insertMany(docs);
  }
  await client.close();
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

export async function startLab({ hardened = false, ports = null, log = () => {} } = {}) {
  const seeds = seedData({ mode: 'local' });
  const servers = [];
  const P = ports || { A: LAB_PORTS.A, A2: LAB_PORTS.A2, B: LAB_PORTS.B, C: LAB_PORTS.C };

  if (!hardened) {
    // NODE A: no-auth 2-member replica set (foothold + topology leak + secrets)
    log(`NODE A: no-auth replica set ${NODES.A.replSet} on ${P.A} + ${P.A2}`);
    const a = await MongoMemoryReplSet.create({
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

  async function teardown() {
    for (const s of servers.slice().reverse()) { try { await s.stop(); } catch { /* ignore */ } }
  }
  return { ports: P, teardown };
}
