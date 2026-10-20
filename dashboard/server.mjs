/*
 * Cloud dashboard (MVP). Receives assessment RESULTS from the local app —
 * never raw access, and passwords are stripped again here on arrival even
 * though the sender already redacted them (defense in depth).
 *
 *   npm run dashboard        # http://127.0.0.1:8901
 *   DASHBOARD_TOKEN=...      # ingest bearer token (default: dev-token)
 *
 * Storage is deliberately boring: one JSON file per run under
 * dashboard/data/<estate>/ (gitignored). Swap for a real DB when it earns it.
 */
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, 'index.html'), 'utf8');
const DATA = process.env.DASH_DATA_DIR || join(HERE, 'data');
const PORT = Number(process.env.DASH_PORT || process.env.PORT || 8901);
const TOKEN = process.env.DASHBOARD_TOKEN || 'dev-token';
mkdirSync(DATA, { recursive: true });

const safeEstate = (s) => String(s || 'unnamed').toLowerCase().replace(/[^a-z0-9-_]+/g, '-').slice(0, 64);
const estateDir = (e) => join(DATA, safeEstate(e));

function stripPasswords(run) {
  const clone = JSON.parse(JSON.stringify(run));
  for (const c of clone.credentials || []) if ('pass' in c) c.pass = '••• stripped at dashboard •••';
  for (const n of clone.nodes || []) if (n.accessCred && 'pass' in n.accessCred) n.accessCred.pass = '••• stripped at dashboard •••';
  return clone;
}

function listRuns(estate) {
  const dir = estateDir(estate);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith('.json')).sort()
    .map((f) => { try { return JSON.parse(readFileSync(join(dir, f), 'utf8')); } catch { return null; } })
    .filter(Boolean);
}

function listEstates() {
  if (!existsSync(DATA)) return [];
  return readdirSync(DATA, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name)
    .map((estate) => {
      const runs = listRuns(estate);
      const latest = runs[runs.length - 1] || null;
      return { estate, runs: runs.length, latest: latest ? { receivedAt: latest.receivedAt, phase: latest.phase, summary: latest.run.summary } : null };
    }).filter((e) => e.runs > 0);
}

const fkey = (f) => `${f.severity}|${f.title}|${f.nodeId}`;
function diffRuns(prev, cur) {
  if (!prev) return null;
  const pNodes = new Set((prev.run.nodes || []).map((n) => n.id));
  const cNodes = new Set((cur.run.nodes || []).map((n) => n.id));
  const pF = new Map((prev.run.findings || []).map((f) => [fkey(f), f]));
  const cF = new Map((cur.run.findings || []).map((f) => [fkey(f), f]));
  return {
    nodesAdded: [...cNodes].filter((x) => !pNodes.has(x)),
    nodesRemoved: [...pNodes].filter((x) => !cNodes.has(x)),
    findingsNew: [...cF.values()].filter((f) => !pF.has(fkey(f))),
    findingsResolved: [...pF.values()].filter((f) => !cF.has(fkey(f))),
    criticalBefore: prev.run.summary.critical,
    criticalAfter: cur.run.summary.critical,
  };
}

function json(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(INDEX); return; }

  if (url.pathname === '/api/ingest' && req.method === 'POST') {
    if ((req.headers.authorization || '') !== `Bearer ${TOKEN}`) return json(res, 401, { error: 'bad token' });
    let body = '';
    for await (const chunk of req) body += chunk;
    try {
      const { estate, phase, run } = JSON.parse(body);
      if (!run || !run.summary) return json(res, 400, { error: 'run payload missing summary' });
      const est = safeEstate(estate);
      mkdirSync(estateDir(est), { recursive: true });
      const receivedAt = new Date().toISOString();
      const record = { receivedAt, phase: phase || 'before', run: stripPasswords(run) };
      writeFileSync(join(estateDir(est), `${receivedAt.replace(/[:.]/g, '-')}.json`), JSON.stringify(record, null, 1));
      return json(res, 201, { ok: true, estate: est, runs: listRuns(est).length });
    } catch (err) { return json(res, 400, { error: String(err?.message || err) }); }
  }

  if (url.pathname === '/api/estates') return json(res, 200, { estates: listEstates() });

  if (url.pathname === '/api/estate') {
    const estate = safeEstate(url.searchParams.get('name'));
    const runs = listRuns(estate);
    if (!runs.length) return json(res, 404, { error: 'unknown estate' });
    const latest = runs[runs.length - 1];
    const prev = runs.length > 1 ? runs[runs.length - 2] : null;
    return json(res, 200, {
      estate,
      trend: runs.map((r) => ({ receivedAt: r.receivedAt, phase: r.phase, summary: r.run.summary })),
      latest: { receivedAt: latest.receivedAt, phase: latest.phase, run: latest.run },
      diff: diffRuns(prev, latest),
    });
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('not found');
});

server.listen(PORT, process.env.HOST || '127.0.0.1', () => {
  const a = server.address();
  console.log(`mongodb-security-lab dashboard → http://${a.address}:${a.port} (data: ${DATA})`);
});
