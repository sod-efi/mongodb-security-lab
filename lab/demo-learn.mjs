/*
 * Self-improvement demo. Boots the vulnerable lab once and runs the SAME
 * assessment several times with learning on. Each run records which
 * credentials, ports and collections produced hits; the next run tries the
 * proven ones first, so the number of authentication attempts drops.
 *
 *   npm run demo:learn
 *
 * Starts from a clean knowledge store so the trend is reproducible.
 */
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { startLab } from './lab.mjs';
import { assess } from '../toolkit/recon.mjs';
import { resetKnowledge } from '../toolkit/lib/memory.mjs';

const KPATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'toolkit', '.memory', 'knowledge.json');
const log = (...a) => console.log('[learn]', ...a);
const RUNS = 3;

log('resetting knowledge store for a clean, reproducible trend');
resetKnowledge(KPATH);

log('booting the vulnerable lab (one entry point, discovery finds the rest)...');
const lab = await startLab({ hardened: false });

const rows = [];
for (let i = 1; i <= RUNS; i++) {
  const json = await assess({
    discover: '127.0.0.1', ports: '27017-27022', lab: true, quiet: true,
    learn: true, learnPath: KPATH,
  });
  const m = json.metrics;
  rows.push({ run: i, attempts: m.authAttempts, ttff: m.timeToFirstFindingMs, findings: m.findings, critical: m.critical });
  log(`run ${i}: authAttempts=${m.authAttempts}  timeToFirstFinding=${m.timeToFirstFindingMs}ms  findings=${m.findings} (${m.critical} critical)`);
}

await lab.teardown();

console.log('\n=============== self-improvement over repeated runs ===============');
console.log(' run | auth attempts | time-to-first-finding | findings');
console.log(' ----+---------------+-----------------------+---------');
for (const r of rows) {
  console.log(`  ${r.run}  |      ${String(r.attempts).padStart(3)}      |        ${String(r.ttff).padStart(4)} ms         |  ${r.findings} (${r.critical} crit)`);
}
const first = rows[0].attempts, last = rows[rows.length - 1].attempts;
const pct = first ? Math.round(((first - last) / first) * 100) : 0;
console.log(' -------------------------------------------------------------------');
console.log(` auth attempts: ${first} -> ${last}  (${pct}% fewer after learning)`);
console.log(' findings stay identical: learning changes the ORDER of probes, not the result.');
console.log(' reset anytime with:  npm run learn:reset');
console.log('===================================================================');
process.exit(0);
