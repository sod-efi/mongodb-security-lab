/*
 * Before/after demo. Runs the assessment against the VULNERABLE lab, then
 * hardens the lab and runs it again, then builds one interactive HTML report
 * whose Before/After toggle shows the map flip from red to green — and opens it.
 *
 *   npm run demo:report
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { platform } from 'node:os';
import { startLab } from './lab.mjs';
import { assess } from '../toolkit/recon.mjs';
import { buildHtml } from '../toolkit/lib/report-html.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'output');
mkdirSync(OUT, { recursive: true });
const log = (...a) => console.log('[demo]', ...a);

// Run the two labs on DISTINCT ports at the same time, so there is no
// teardown-then-rebind of the same port (which Windows TIME_WAIT can disrupt).
log('=== PHASE 1: assessing the VULNERABLE cluster (ports 27018-27021) ===');
const vuln = await startLab({ hardened: false });
const before = await assess({ discover: '127.0.0.1', ports: '27017-27022', lab: true, learn: false });
log(`vulnerable: ${before.summary.critical} critical finding(s)`);

log('\n=== PHASE 2: the SAME cluster, hardened (ports 27030-27032) ===');
log('applied fixes: auth on every node, strong unique passwords, secrets removed, no default creds');
const hard = await startLab({ hardened: true, ports: { A: 27030, B: 27031, C: 27032 } });
const after = await assess({ discover: '127.0.0.1', ports: '27030-27033', lab: true, learn: false });
log(`hardened: ${after.summary.critical} critical finding(s)`);

await hard.teardown();
await vuln.teardown();

const html = buildHtml({ before, after });
const htmlPath = join(OUT, 'report.html');
writeFileSync(htmlPath, html);
writeFileSync(join(OUT, 'findings-before.json'), JSON.stringify(before, null, 2));
writeFileSync(join(OUT, 'findings-after.json'), JSON.stringify(after, null, 2));

log(`\nreport written: ${htmlPath}`);
log(`red -> green: ${before.summary.critical} critical  ->  ${after.summary.critical} critical`);

// Open in the default browser (best effort; set NO_OPEN=1 to skip).
if (process.env.NO_OPEN) { log('open output/report.html in a browser to view it.'); process.exit(0); }
try {
  const p = platform();
  const [cmd, args] = p === 'win32' ? ['cmd', ['/c', 'start', '', htmlPath]]
    : p === 'darwin' ? ['open', [htmlPath]]
    : ['xdg-open', [htmlPath]];
  spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref();
  log('opening report in your browser...');
} catch {
  log('open output/report.html in a browser to view it.');
}
process.exit(0);
