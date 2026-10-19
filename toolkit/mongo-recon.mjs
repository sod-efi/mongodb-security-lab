#!/usr/bin/env node
/*
 * mongo-recon — authorized MongoDB cluster assessment / lateral-movement PoC.
 * Thin CLI around toolkit/recon.mjs (assess). READ-ONLY; lab/private scope.
 *
 * Usage:
 *   node toolkit/mongo-recon.mjs --seed 127.0.0.1:27018 --lab
 *   node toolkit/mongo-recon.mjs --discover 127.0.0.1 --ports 27017-27022 --lab
 *   node toolkit/mongo-recon.mjs --seed 10.0.0.5:27017 --cred user:pass
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { banner } from './lib/safety.mjs';
import { assess } from './recon.mjs';
import { buildHtml } from './lib/report-html.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'output');
const argv = process.argv.slice(2);
const getArg = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const hasFlag = (name) => argv.includes(name);

const seed = getArg('--seed');
const discover = getArg('--discover');
const ports = getArg('--ports');
const lab = hasFlag('--lab');
const allowExternal = hasFlag('--authorized-external');
const learn = !hasFlag('--no-learn');
const resetLearning = hasFlag('--reset-learning');
const extraCreds = argv
  .filter((a, i) => argv[i - 1] === '--cred')
  .map((s) => { const [user, ...rest] = s.split(':'); return { user, pass: rest.join(':'), authSource: 'admin' }; });

if (!seed && !discover) {
  console.error('usage: node toolkit/mongo-recon.mjs (--seed host:port | --discover host|CIDR) [--ports 27017-27021] [--lab] [--cred user:pass] [--authorized-external]');
  process.exit(2);
}

console.log(banner());

const json = await assess({ seed, discover, ports, lab, allowExternal, extraCreds, learn, resetLearning, writeFiles: true, outDir: OUT });
writeFileSync(join(OUT, 'report.html'), buildHtml({ before: json }));

const m = json.metrics;
console.log('\n======================== SUMMARY ========================');
console.log(` nodes discovered      : ${json.summary.nodesDiscovered}`);
console.log(` credentials harvested : ${json.summary.credentialsHarvested}`);
console.log(` findings              : ${json.summary.findings} (${json.summary.critical} critical)`);
if (m?.learning) {
  const prev = m.previous ? ` (prev run: ${m.previous.authAttempts})` : ' (first learned run)';
  console.log(` auth attempts         : ${m.authAttempts}${prev}  [learning on]`);
  console.log(` time to first finding : ${m.timeToFirstFindingMs} ms`);
}
console.log(' reports:');
console.log('   output/findings.json   (machine-readable picture)');
console.log('   output/network-map.md  (Mermaid map + findings)');
console.log('   output/report.html     (interactive report)');
console.log('=========================================================');
