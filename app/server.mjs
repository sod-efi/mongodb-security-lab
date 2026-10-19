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

function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
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
    sse(res, 'done', { phase, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings });
  } else {
    sse(res, 'status', { message: 'Starting the demo cluster…' });
    const lab = await startLab({ hardened: false });
    let json;
    try {
      const seed = `127.0.0.1:${lab.ports.A}`;
      sse(res, 'status', { message: `One entry point: ${seed}. Everything else, the tool has to discover itself…`, seed });
      json = await assess({ seed, lab: true, learn: false, quiet: true, onEvent });
    } finally { await lab.teardown(); }
    sse(res, 'done', { phase, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings });
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(INDEX);
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

server.listen(PORT, '127.0.0.1', () => {
  console.log(`mongodb-security-lab app → http://127.0.0.1:${PORT}`);
});
