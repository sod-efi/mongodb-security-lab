/*
 * The drift agent. Runs the assessment against YOUR clusters on a
 * schedule and sends each redacted result to your dashboard, which diffs
 * it against the previous run — that diff is the drift alert.
 *
 *   cp agent/config.example.json agent/config.json   # edit it
 *   npm run agent               # loop on the configured interval
 *   npm run agent -- --once     # a single pass (cron/systemd friendly)
 *
 * Config (agent/config.json, gitignored — it holds your credential):
 *   estate         name shown on the dashboard
 *   dashboardUrl   e.g. https://your-dashboard.up.railway.app
 *   token          dashboard ingest token (or set DASHBOARD_TOKEN env)
 *   intervalSeconds  between passes in loop mode (default 3600)
 *   targets[]      { mode: "seed"|"scan", host, port, portRange,
 *                    credUser, credPass, credAuthSource, authorizedExternal }
 *
 * Scope rules are the engine's own: loopback/RFC1918 unless a target sets
 * authorizedExternal. Results are redacted (toolkit/lib/redact.mjs)
 * before they leave this machine; raw credentials from config are used
 * only to authenticate to YOUR nodes and are never sent anywhere.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { assess } from '../toolkit/recon.mjs';
import { redactRun } from '../toolkit/lib/redact.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = process.env.AGENT_CONFIG || join(HERE, 'config.json');
const STATE_PATH = join(HERE, '.state.json');
const once = process.argv.includes('--once');
const log = (...a) => console.log('[agent]', new Date().toISOString(), ...a);

if (!existsSync(CONFIG_PATH)) {
  console.error('[agent] no config found — copy agent/config.example.json to agent/config.json and edit it.');
  process.exit(1);
}
const cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
const token = process.env.DASHBOARD_TOKEN || cfg.token || '';
const intervalMs = Math.max(10, Number(cfg.intervalSeconds || 3600)) * 1000;

function loadState() { try { return JSON.parse(readFileSync(STATE_PATH, 'utf8')); } catch { return {}; } }
function saveState(s) { try { writeFileSync(STATE_PATH, JSON.stringify(s, null, 1)); } catch { /* state is a nicety, not a requirement */ } }

const fkey = (f) => `${f.severity}|${f.title}|${f.nodeId}`;

async function runTarget(t) {
  const extraCreds = t.credUser ? [{ user: t.credUser, pass: t.credPass || '', authSource: t.credAuthSource || 'admin' }] : [];
  const opts = { lab: false, learn: false, quiet: true, allowExternal: Boolean(t.authorizedExternal), extraCreds };
  const json = t.mode === 'scan'
    ? await assess({ ...opts, discover: t.host, ports: t.portRange || '27017-27030' })
    : await assess({ ...opts, seed: `${t.host}:${t.port || 27017}` });
  return { generatedAt: json.generatedAt, summary: json.summary, nodes: json.nodes, edges: json.edges, credentials: json.credentials, findings: json.findings };
}

async function send(payload, phase) {
  const url = String(cfg.dashboardUrl || '').replace(/\/$/, '') + '/api/ingest';
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ estate: cfg.estate || 'unnamed-estate', phase, run: redactRun(payload) }),
  });
  if (!r.ok) throw new Error(`dashboard said ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

async function pass() {
  const state = loadState();
  for (const t of cfg.targets || []) {
    const label = t.mode === 'scan' ? `${t.host} scan ${t.portRange || ''}` : `${t.host}:${t.port || 27017}`;
    try {
      const payload = await runTarget(t);
      await send(payload, 'agent');
      const prev = state[label];
      const curKeys = new Set(payload.findings.map(fkey));
      let drift = 'first run — baseline set';
      if (prev) {
        const prevKeys = new Set(prev.findingKeys || []);
        const added = [...curKeys].filter((k) => !prevKeys.has(k)).length;
        const resolved = [...prevKeys].filter((k) => !curKeys.has(k)).length;
        drift = `critical ${prev.critical} → ${payload.summary.critical} · findings +${added} / −${resolved}`;
      }
      log(`${label}: nodes=${payload.summary.nodesDiscovered} creds=${payload.summary.credentialsHarvested} findings=${payload.summary.findings} critical=${payload.summary.critical} · ${drift} · sent to dashboard`);
      state[label] = { at: new Date().toISOString(), critical: payload.summary.critical, findingKeys: [...curKeys] };
    } catch (err) {
      log(`${label}: FAILED — ${String(err?.message || err)}`);
    }
  }
  saveState(state);
}

log(`estate="${cfg.estate}" targets=${(cfg.targets || []).length} dashboard=${cfg.dashboardUrl} mode=${once ? 'once' : `loop every ${intervalMs / 1000}s`}`);
await pass();
if (!once) {
  setInterval(pass, intervalMs);
} else {
  process.exit(0);
}
