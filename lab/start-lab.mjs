/*
 * No-Docker lab runner. Boots the three-node cluster (real mongod via
 * mongodb-memory-server) and optionally runs the assessment against it.
 *
 *   node lab/start-lab.mjs                  # bring the lab up, keep it running
 *   node lab/start-lab.mjs --hardened       # bring up the SECURE variant
 *   node lab/start-lab.mjs --run-demo        # up, assess (seed), tear down
 *   node lab/start-lab.mjs --run-demo --discover   # up, assess (port-sweep), tear down
 *
 * AUTHORIZED LAB USE ONLY. Everything binds to 127.0.0.1.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { startLab } from './lab.mjs';
import { assess } from '../toolkit/recon.mjs';
import { buildHtml } from '../toolkit/lib/report-html.mjs';
import { banner } from '../toolkit/lib/safety.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'output');
mkdirSync(OUT, { recursive: true });
const log = (...a) => console.log('[lab]', ...a);

const hardened = process.argv.includes('--hardened');
const demo = process.argv.includes('--run-demo');
const discover = process.argv.includes('--discover');

const { ports, teardown } = await startLab({ hardened, log });
writeFileSync(join(OUT, 'lab-state.json'), JSON.stringify({ startedAt: new Date().toISOString(), hardened, ports }, null, 2));
log(`lab is UP (${hardened ? 'HARDENED' : 'vulnerable'}). Ports: ${JSON.stringify(ports)}`);

if (demo) {
  console.log(banner());
  const json = await assess({
    seed: discover ? null : `127.0.0.1:${ports.A}`,
    discover: discover ? '127.0.0.1' : null,
    ports: discover ? '27017-27022' : null,
    lab: true,
    writeFiles: true,
    outDir: OUT,
  });
  writeFileSync(join(OUT, 'report.html'), buildHtml({ before: json }));
  console.log(`\nnodes=${json.summary.nodesDiscovered} findings=${json.summary.findings} critical=${json.summary.critical}`);
  console.log('reports in output/: findings.json, network-map.md, report.html');
  await teardown();
  process.exit(0);
} else {
  log('Assess it from another terminal:');
  log(`  node toolkit/mongo-recon.mjs --discover 127.0.0.1 --ports 27017-27022 --lab`);
  process.on('SIGINT', async () => { log('tearing down...'); await teardown(); process.exit(0); });
  process.on('SIGTERM', async () => { await teardown(); process.exit(0); });
  setInterval(() => {}, 1 << 30);
}
