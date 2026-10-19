/*
 * The assessment engine, as an importable function. The CLI (mongo-recon.mjs)
 * and the before/after demo (lab/demo-report.mjs) both call assess().
 *
 * READ-ONLY. Scope is enforced per target via safety.assertInScope.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertInScope } from './lib/safety.mjs';
import { fingerprint, tryAccess, whoAmI, harvest, authWorks } from './lib/enumerate.mjs';
import { parseMongoUri } from './lib/secrets.mjs';
import { ClusterGraph } from './lib/graph.mjs';
import { DEFAULT_CREDS } from './lib/wordlist.mjs';
import { sweep } from './lib/discover.mjs';
import {
  loadKnowledge, saveKnowledge, resetKnowledge, credKey,
  rankOpenPorts, rankDefaults, provenCredsForPort, provenDefaultForPort, defaultsProbed,
  recordCred, recordPortCred, markDefaultsProbed, recordPort, recordColl,
} from './lib/memory.mjs';

const DEFAULT_LEARN_PATH = join(dirname(fileURLToPath(import.meta.url)), '.memory', 'knowledge.json');

export async function assess({
  seed = null,
  discover = null,
  ports = null,
  lab = false,
  allowExternal = false,
  extraCreds = [],
  quiet = false,
  writeFiles = false,
  outDir = null,
  learn = true,
  learnPath = DEFAULT_LEARN_PATH,
  resetLearning = false,
  onEvent = null,
} = {}) {
  const log = quiet ? () => {} : (...a) => console.log(...a);

  // ---- self-improvement: load what prior runs learned --------------------
  if (resetLearning) resetKnowledge(learnPath);
  const K = learn ? loadKnowledge(learnPath) : null;
  const rankedDefaults = K ? rankDefaults(K, DEFAULT_CREDS) : DEFAULT_CREDS;
  const t0 = Date.now();
  let firstFindingMs = null;
  let authAttempts = 0;

  // In lab mode, replica-set members may be advertised under an internal
  // hostname; remap to loopback at the same port so we can actually reach them.
  const reachable = (host, port) =>
    (lab && host !== '127.0.0.1' && host !== 'localhost') ? { host: '127.0.0.1', port } : { host, port };

  const graph = new ClusterGraph({ onEvent });
  const seen = new Set();
  const credPool = [...extraCreds];
  const queue = [];
  const dedupCreds = (list) => {
    const seenK = new Set();
    return list.filter((c) => { const k = credKey(c); if (seenK.has(k)) return false; seenK.add(k); return true; });
  };

  function enqueue(host, port, fromId, reason) {
    const id = `${host}:${port}`;
    if (seen.has(id)) { graph.edge(fromId, id, reason); return; }
    seen.add(id);
    queue.push({ host, port, fromId, reason });
  }

  function recordTopology(fp, nodeId) {
    if (fp.setName && fp.members?.length) {
      graph.addFinding(nodeId, 'MEDIUM', 'Replica-set topology disclosed pre-auth',
        `The hello/isMaster handshake (which requires no authentication) revealed replica set \`${fp.setName}\` and member hosts: ${fp.members.join(', ')}. This maps internal infrastructure for an attacker.`,
        'Place replica-set traffic on a private network, restrict who can reach the port, and consider TLS with client-cert auth so unauthenticated peers cannot complete the handshake.');
      for (const m of fp.members) {
        const [mh, mp] = m.split(':');
        enqueue(mh, Number(mp || 27017), nodeId, `replica-set member of ${fp.setName}`);
      }
    }
  }

  // ---- discovery (optional) ----------------------------------------------
  if (discover) {
    log(`\n[discovery] TCP connect-scan of ${discover} ports ${ports || '27017-27021 (default)'} ...`);
    const res = await sweep(discover, ports, { allowExternal, onOpen: (id) => log(`   open: ${id}`) });
    log(`[discovery] ${res.open.length} open / ${res.scanned} probed across ${res.hosts} host(s)` +
      (res.refused ? `  (${res.refused} out-of-scope host(s) skipped)` : ''));
    // Assess ports that have hosted a node before, first (faster first finding).
    const openIds = K ? rankOpenPorts(K, res.open) : res.open;
    for (const id of openIds) { const [dh, dp] = id.split(':'); enqueue(dh, Number(dp), null, 'discovered open port'); }
  }

  if (seed) { const [sh, sp] = seed.split(':'); enqueue(sh, Number(sp || 27017), null, 'seed'); }

  // ---- BFS pivot ----------------------------------------------------------
  let step = 0;
  while (queue.length) {
    const { host, port, fromId, reason } = queue.shift();
    const tgt = reachable(host, port);
    step++;
    log(`\n[${step}] -- target ${host}:${port}  (via: ${reason})`);

    try { assertInScope(tgt.host, { allowExternal }); }
    catch (e) { log('   ' + e.message); continue; }

    const fp = await fingerprint(tgt.host, tgt.port);
    const nodeId = graph.upsert(host, port, {
      version: fp.version, authRequired: fp.authRequired, setName: fp.setName,
      advertisedMembers: fp.members, discoveredVia: reason,
    });
    graph.edge(fromId, nodeId, reason);

    if (!fp.reachable) { log(`   unreachable (${fp.reason})`); continue; }
    if (K) recordPort(K, port);
    log(`   mongod ${fp.version || '?'}  auth=${fp.authRequired ? 'required' : 'NONE'}` +
      (fp.setName ? `  replicaSet=${fp.setName}` : ''));

    // weak/default credential probe. Learning narrows this: if a default
    // worked on this port before, try just that one; if the full list was
    // probed before and never hit, skip it entirely.
    let weakHit = null; // the (usually admin) default cred that works here
    if (fp.authRequired) {
      const knownDefault = K ? provenDefaultForPort(K, port, DEFAULT_CREDS) : null;
      const skipProbe = K && !knownDefault && defaultsProbed(K, port);
      const toProbe = knownDefault ? [knownDefault] : (skipProbe ? [] : rankedDefaults);
      for (const dc of toProbe) {
        authAttempts++;
        if (await authWorks(tgt.host, tgt.port, dc)) {
          weakHit = dc;
          const shown = dc.pass === '' ? '(empty)' : dc.pass;
          log(`   WEAK/DEFAULT credential accepted: ${dc.user}:${shown}`);
          if (K) { recordCred(K, dc); recordPortCred(K, port, dc); }
          graph.addCredential({ ...dc, foundAt: '(default-cred guess)' }, '(default-cred guess)');
          graph.addFinding(nodeId, 'CRITICAL', 'Default/weak administrative credential',
            `The node authenticates a well-known default credential \`${dc.user}:${shown}\`, which typically grants administrative control of the node.`,
            'Remove default accounts, set strong unique passwords, prefer SCRAM-SHA-256 or x.509 client certs, and alert on logins using default usernames.');
          break;
        }
      }
      if (K && !knownDefault && !skipProbe) markDefaultsProbed(K, port);
    }

    // Does a credential stored on another node target THIS node? This makes
    // the credential-reuse finding deterministic: it depends on what was found
    // stored, not on which credential happened to win the access race (so
    // learning-driven reordering never changes the findings).
    const reused = credPool.find((c) => c.foundAt && c.targets?.includes(`${host}:${port}`));

    // gain access. Try this port's proven creds first; skip the pointless
    // anonymous attempt on auth-required nodes.
    const provenForPort = K ? provenCredsForPort(K, port) : [];
    const credList = dedupCreds([...provenForPort, ...credPool, ...rankedDefaults]);
    const access = await tryAccess(tgt.host, tgt.port, credList, { includeAnon: !fp.authRequired });
    authAttempts += access.attempts || 0;
    if (!access.ok) {
      log('   no read access (auth required, no working credential yet)');
      graph.addFinding(nodeId, 'INFO', 'Authentication enforced',
        'Node required authentication and no harvested/default credential worked at the time it was reached.',
        'N/A -- expected hardening.');
      recordTopology(fp, nodeId);
      continue;
    }

    const usedCred = access.cred;
    if (K && usedCred) { recordCred(K, usedCred); recordPortCred(K, port, usedCred); }
    graph.upsert(host, port, { accessCred: usedCred });
    if (!usedCred) {
      log('   READ ACCESS with NO CREDENTIALS (unauthenticated).');
      graph.addFinding(nodeId, 'CRITICAL', 'Unauthenticated database access',
        'The node accepts anonymous connections and exposes application data without any authentication. Anyone who can reach the port has full read (and likely write) access.',
        'Enable access control (security.authorization: enabled), create least-privilege users, and firewall the port so it is not reachable from untrusted networks. Bind to private interfaces only.');
    } else {
      log(`   READ ACCESS as "${usedCred.user}"${usedCred.foundAt ? ' (harvested credential)' : ' (proven/supplied credential)'}`);
      graph.addCredential(usedCred, usedCred.foundAt || '(operator-supplied)');
    }
    if (reused) {
      graph.addFinding(nodeId, 'CRITICAL', 'Credential reuse enabled pivot',
        `A working credential for this node (\`${reused.user}\`) was found stored in plaintext on ${reused.foundAt}. Storing downstream connection strings in the database let one compromise cascade here.`,
        'Never store plaintext connection strings/secrets in application collections. Use a secrets manager, scope credentials per service, and rotate anything exposed.');
    }

    // privilege picture — use the most-privileged credential known for this
    // node (the weak-probe admin hit when present) so the finding set is
    // complete and the same whether or not learning picked a lesser cred first.
    try {
      const who = await whoAmI(tgt.host, tgt.port, weakHit || usedCred);
      const roles = (who.authenticatedUserRoles || []).map((r) => `${r.role}@${r.db}`).join(', ') || '(none)';
      log(`   privileges: ${roles}`);
      if (who.allUsers?.length) {
        log(`   can read user list: ${who.allUsers.map((u) => `${u.user}@${u.db}`).join(', ')}`);
        graph.addFinding(nodeId, 'HIGH', 'User catalogue readable',
          `Current principal can enumerate all database users: ${who.allUsers.map((u) => `${u.user}@${u.db}`).join(', ')}.`,
          'Restrict userAdmin/viewUser privileges to dedicated admin principals; application users should not hold them.');
      }
      graph.upsert(host, port, { roles: who.authenticatedUserRoles, allUsers: who.allUsers });
    } catch { /* ignore */ }

    // enumerate + harvest (collections that held secrets before, first)
    const loot = await harvest(tgt.host, tgt.port, usedCred, access.databases, K ? K.secretCollections : null);
    const dbSummary = {};
    for (const [db, colls] of Object.entries(loot.databases)) {
      dbSummary[db] = colls;
      const cc = Object.entries(colls).map(([c, m]) => `${c}:${m.count}`).join(', ');
      log(`   db ${db}: ${cc || '(no readable collections)'}`);
    }
    graph.upsert(host, port, { databases: dbSummary });

    if (loot.secrets.length) {
      log(`   harvested ${loot.secrets.length} secret-looking field(s) and ${loot.uris.length} connection URI(s)`);
      graph.addFinding(nodeId, 'HIGH', 'Secrets stored in application data',
        `Found ${loot.secrets.length} secret-bearing field(s) in collections (e.g. ${loot.secrets.slice(0, 3).map((s) => s.field).join(', ')}). These include credentials/keys that enable further compromise.`,
        'Move secrets out of the database into a managed secret store; scrub existing documents and rotate exposed values.');
      if (K) for (const s of loot.secrets) { const m = /\.([^.]+)$/.exec(s.source || ''); if (m) recordColl(K, m[1]); }
    }

    // harvested URIs -> pivot targets + creds
    for (const uri of loot.uris) {
      const p = parseMongoUri(uri);
      if (!p) continue;
      const targets = p.hosts.map((h) => `${h.host}:${h.port}`);
      if (p.user) {
        credPool.unshift({ user: p.user, pass: p.pass, authSource: p.authSource || p.db || 'admin', foundAt: nodeId, targets });
        graph.addCredential({ user: p.user, pass: p.pass, authSource: p.authSource || p.db }, nodeId);
      }
      for (const h of p.hosts) enqueue(h.host, h.port, nodeId, 'harvested connection string');
    }

    recordTopology(fp, nodeId);
    if (firstFindingMs === null && graph.findings.length > 0) firstFindingMs = Date.now() - t0;
  }

  // ---- self-improvement: measure this run and save what it learned -------
  const json = graph.toJSON();
  const metrics = {
    learning: Boolean(K),
    runIndex: K ? K.runs.length + 1 : null,
    authAttempts,
    timeToFirstFindingMs: firstFindingMs,
    totalMs: Date.now() - t0,
    findings: json.summary.findings,
    critical: json.summary.critical,
    previous: null,
  };
  if (K) {
    const prev = K.runs[K.runs.length - 1] || null;
    if (prev) metrics.previous = { authAttempts: prev.authAttempts, timeToFirstFindingMs: prev.timeToFirstFindingMs };
    K.runs.push({ at: new Date().toISOString(), authAttempts, timeToFirstFindingMs: firstFindingMs, totalMs: metrics.totalMs, findings: metrics.findings, critical: metrics.critical });
    saveKnowledge(learnPath, K);
  }
  json.metrics = metrics;

  if (writeFiles && outDir) {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'findings.json'), JSON.stringify(json, null, 2));
    writeFileSync(join(outDir, 'network-map.md'), graph.markdown());
  }
  return json;
}
