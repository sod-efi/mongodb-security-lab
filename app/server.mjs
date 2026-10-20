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

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(join(HERE, 'index.html'), 'utf8');
const PORT = Number(process.env.PORT || 8900);

let busy = false;
let lastRun = null; // { phase, payload } of the most recent finished run

function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// The trust contract, in code: this is the ONLY transformation applied
// before a result may leave the machine, and the UI shows the user the
// exact redacted payload before sending. Passwords never leave; the
// dashboard strips them again server-side as defense in depth.
function redactRun(payload) {
  const clone = JSON.parse(JSON.stringify(payload));
  for (const c of clone.credentials || []) if ('pass' in c) c.pass = '••• redacted •••';
  for (const n of clone.nodes || []) if (n.accessCred && 'pass' in n.accessCred) n.accessCred.pass = '••• redacted •••';
  return clone;
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
  if (url.pathname === '/api/run') {
    if (busy) { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'an assessment is already running' })); return; }
    busy = true;
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    try {
      await runPhase(res, url.searchParams.get('phase') === 'after' ? 'after' : 'before');
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
