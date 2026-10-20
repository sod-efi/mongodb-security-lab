/*
 * The production-app demo. A tiny zero-dependency HTTP server that serves
 * the single-page UI and streams a LIVE lab assessment to it over SSE.
 *
 *   npm run app          # http://127.0.0.1:8900
 *
 * Flow (the story the UI tells): one entry point is given; the assessment
 * reconstructs the whole cluster from it, live — nodes pop onto the graph
 * as they are discovered, findings stream in as they are proven. A second
 * phase hardens the cluster and re-scans, and the picture flips green.
 *
 * Targets are generated internally (the built-in lab on loopback). The
 * engine's own scope enforcement (toolkit/lib/safety.mjs) still applies to
 * every connection. Nothing here accepts a user-supplied target.
 */
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { startLab } from '../lab/lab.mjs';
import { assess } from '../toolkit/recon.mjs';
import { assertInScope } from '../toolkit/lib/safety.mjs';
import { redactRun } from '../toolkit/lib/redact.mjs';

// Hosted-demo mode: the own-cluster form is disabled entirely. A public
// deployment must never become a scanner other people aim at networks.
const DEMO_ONLY = process.env.DEMO_ONLY === '1';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, 'index.html'), 'utf8');
const PORT = Number(process.env.PORT || 8900);

let busy = false;
let lastRun = null; // { phase, payload } of the most recent finished run

function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// The trust contract lives in toolkit/lib/redact.mjs (shared with the
// agent): passwords never leave the machine, and the UI shows the user
// the exact redacted payload before sending.

// Own-cluster runs are started via POST (credentials travel in the POST
// body, never in a URL), stored under a one-time id in memory only, and
// deleted the moment the run begins. Nothing is written to disk.
const pendingOwn = new Map();

async function runOwn(res, p) {
  const onEvent = (e) => sse(res, 'progress', e);
  const extraCreds = p.credUser ? [{ user: p.credUser, pass: p.credPass || '', authSource: p.credAuthSource || 'admin' }] : [];
  const opts = { lab: false, learn: false, quiet: true, onEvent, allowExternal: p.authorizedExternal, extraCreds };
  if (p.mode === 'scan') {
    sse(res, 'status', { message: `Scanning ${p.host} ports ${p.portRange} for MongoDB nodes…`, seed: `${p.host} · scan ${p.portRange}` });
    const json = await assess({ ...opts, discover: p.host, ports: p.portRange });
    lastRun = { phase: 'own', payload: { generatedAt: json.generatedAt, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings } };
  } else {
    const seed = `${p.host}:${p.port}`;
    sse(res, 'status', { message: `One entry point: ${seed}. Reconstructing the cluster from there…`, seed });
    const json = await assess({ ...opts, seed });
    lastRun = { phase: 'own', payload: { generatedAt: json.generatedAt, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings } };
  }
  sse(res, 'done', { phase: 'own', ...lastRun.payload });
}

async function runPhase(res, phase) {
  const onEvent = (e) => sse(res, 'progress', e);
  // 'done' is sent only AFTER teardown completes: the client enables its
  // next action on 'done', and the server must actually be free by then —
  // otherwise an immediate follow-up run hits the busy guard and stalls.
  if (phase === 'after') {
    sse(res, 'status', { message: 'Starting the hardened cluster — same layout, every fix applied…' });
    const lab = await startLab({ hardened: true, ports: { A: 27030, B: 27031, C: 27032 } });
    let json;
    try {
      sse(res, 'status', { message: 'Scanning the hardened cluster — watch what the entry point can still reach…' });
      json = await assess({ discover: '127.0.0.1', ports: '27030-27033', lab: true, learn: false, quiet: true, onEvent });
    } finally { await lab.teardown(); }
    lastRun = { phase, payload: { generatedAt: json.generatedAt, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings } };
    sse(res, 'done', { phase, ...lastRun.payload });
  } else {
    sse(res, 'status', { message: 'Starting the demo cluster…' });
    const lab = await startLab({ hardened: false });
    let json;
    try {
      const seed = `127.0.0.1:${lab.ports.A}`;
      sse(res, 'status', { message: `One entry point: ${seed}. Everything else, the tool has to discover itself…`, seed });
      json = await assess({ seed, lab: true, learn: false, quiet: true, onEvent });
    } finally { await lab.teardown(); }
    lastRun = { phase, payload: { generatedAt: json.generatedAt, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings } };
    sse(res, 'done', { phase, ...lastRun.payload });
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(INDEX);
    return;
  }
  if (url.pathname === '/api/last-run') {
    if (!lastRun) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'no run yet' })); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ phase: lastRun.phase, payload: redactRun(lastRun.payload) }));
    return;
  }
  if (url.pathname === '/api/send' && req.method === 'POST') {
    if (!lastRun) { res.writeHead(404, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'no run yet' })); return; }
    let body = '';
    for await (const chunk of req) body += chunk;
    try {
      const { url: dashUrl, token, estate } = JSON.parse(body || '{}');
      const target = String(dashUrl || '').replace(/\/$/, '') + '/api/ingest';
      const r = await fetch(target, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token || ''}` },
        body: JSON.stringify({ estate: String(estate || 'unnamed-estate'), phase: lastRun.phase, run: redactRun(lastRun.payload) }),
      });
      const text = await r.text();
      res.writeHead(r.ok ? 200 : 502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: r.ok, status: r.status, dashboard: text.slice(0, 300) }));
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: String(err?.message || err) }));
    }
    return;
  }
  if (url.pathname === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ demoOnly: DEMO_ONLY }));
    return;
  }
  if (url.pathname === '/api/own-run/start' && req.method === 'POST') {
    if (DEMO_ONLY) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'own-cluster assessments are disabled in the hosted demo — download the app to scan your own systems' })); return; }
    let body = '';
    for await (const chunk of req) body += chunk;
    try {
      const p = JSON.parse(body || '{}');
      const host = String(p.host || '').trim();
      const port = Math.min(65535, Math.max(1, Number(p.port || 27017)));
      const mode = p.mode === 'scan' ? 'scan' : 'seed';
      const portRange = String(p.portRange || '27017-27030').trim();
      if (!host) throw new Error('host is required');
      if (mode === 'scan' && !/^\d{1,5}(-\d{1,5})?$/.test(portRange)) throw new Error('port range looks wrong (e.g. 27017-27030)');
      // Scope is pre-checked here so a refusal is a clean form error, and
      // re-checked by the engine for every node it pivots to.
      assertInScope(host, { allowExternal: Boolean(p.authorizedExternal) });
      const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
      pendingOwn.set(id, {
        host, port, mode, portRange,
        credUser: String(p.credUser || ''), credPass: String(p.credPass || ''), credAuthSource: String(p.credAuthSource || 'admin'),
        authorizedExternal: Boolean(p.authorizedExternal),
      });
      setTimeout(() => pendingOwn.delete(id), 60_000).unref();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(err?.message || err) }));
    }
    return;
  }
  if (url.pathname === '/api/run') {
    if (busy) { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'an assessment is already running' })); return; }
    const ownId = url.searchParams.get('own');
    const ownParams = ownId ? pendingOwn.get(ownId) : null;
    if (ownId) pendingOwn.delete(ownId);
    busy = true;
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    try {
      if (ownId && !ownParams) sse(res, 'failed', { message: 'that run link expired or was already used — submit the form again' });
      else if (ownParams) await runOwn(res, ownParams);
      else await runPhase(res, url.searchParams.get('phase') === 'after' ? 'after' : 'before');
    } catch (err) {
      sse(res, 'failed', { message: String(err?.message || err) });
    } finally {
      busy = false;
      res.end();
    }
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
});

const HOST = process.env.HOST || '127.0.0.1';
server.listen(PORT, HOST, () => {
  console.log(`mongodb-security-lab app → http://${HOST}:${PORT}`);
});
