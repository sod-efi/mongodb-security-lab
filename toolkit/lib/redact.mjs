/*
 * The trust contract, as a shared module: before an assessment result
 * leaves the machine (agent or app → dashboard), passwords are replaced.
 * Everything else in the payload was already safe to share — findings,
 * the graph, and a data inventory whose sample documents were redacted
 * at harvest time (see enumerate.mjs). The dashboard strips passwords a
 * second time on arrival, as defense in depth.
 */
export function redactRun(payload) {
  const clone = JSON.parse(JSON.stringify(payload));
  for (const c of clone.credentials || []) if ('pass' in c) c.pass = '••• redacted •••';
  for (const n of clone.nodes || []) if (n.accessCred && 'pass' in n.accessCred) n.accessCred.pass = '••• redacted •••';
  return clone;
}
