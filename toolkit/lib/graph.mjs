/*
 * Accumulates the discovered cluster into a graph (nodes = mongod instances,
 * edges = how we pivoted to each) and renders JSON + a Markdown report with a
 * Mermaid network diagram.
 */
export class ClusterGraph {
  constructor() {
    this.nodes = new Map();   // "host:port" -> node record
    this.edges = [];          // { from, to, reason }
    this.findings = [];       // { nodeId, severity, title, detail, remediation }
    this.credentials = [];    // { user, pass, scope, foundAt }
  }

  key(host, port) { return `${host}:${port}`; }

  upsert(host, port, attrs = {}) {
    const id = this.key(host, port);
    const cur = this.nodes.get(id) || { id, host, port, databases: {} };
    this.nodes.set(id, { ...cur, ...attrs });
    return id;
  }

  edge(fromId, toId, reason) {
    if (!fromId || fromId === toId) return; // no seed predecessor / no self-loops
    if (this.edges.some((e) => e.from === fromId && e.to === toId && e.reason === reason)) return;
    this.edges.push({ from: fromId, to: toId, reason });
  }

  addFinding(nodeId, severity, title, detail, remediation) {
    this.findings.push({ nodeId, severity, title, detail, remediation });
  }

  addCredential(cred, foundAt) {
    if (!cred?.user) return;
    const dup = this.credentials.find((c) => c.user === cred.user && c.pass === cred.pass);
    if (dup) return;
    this.credentials.push({ user: cred.user, pass: cred.pass, scope: cred.authSource || cred.db || 'admin', foundAt });
  }

  toJSON() {
    return {
      generatedAt: new Date().toISOString(),
      summary: {
        nodesDiscovered: this.nodes.size,
        credentialsHarvested: this.credentials.length,
        findings: this.findings.length,
        critical: this.findings.filter((f) => f.severity === 'CRITICAL').length,
      },
      nodes: [...this.nodes.values()],
      edges: this.edges,
      credentials: this.credentials,
      findings: this.findings,
    };
  }

  mermaid() {
    const lines = ['```mermaid', 'graph LR'];
    for (const n of this.nodes.values()) {
      const safe = n.id.replace(/[.:]/g, '_');
      const auth = n.authRequired === false ? 'NO AUTH' : (n.accessCred ? `auth:${n.accessCred.user}` : 'auth');
      const ver = n.version ? ` v${n.version}` : '';
      const rs = n.setName ? ` {${n.setName}}` : '';
      const crit = this.findings.some((f) => f.nodeId === n.id && f.severity === 'CRITICAL');
      lines.push(`  ${safe}["${n.host}:${n.port}${ver}${rs}<br/>${auth}"]${crit ? ':::crit' : ''}`);
    }
    for (const e of this.edges) {
      lines.push(`  ${e.from.replace(/[.:]/g, '_')} -->|${e.reason}| ${e.to.replace(/[.:]/g, '_')}`);
    }
    lines.push('  classDef crit fill:#ffdddd,stroke:#c0392b,stroke-width:2px;');
    lines.push('```');
    return lines.join('\n');
  }

  markdown() {
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    const findings = [...this.findings].sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);
    const out = [];
    out.push('# MongoDB cluster assessment — findings');
    out.push('');
    out.push(`_Generated ${new Date().toISOString()} · lab assessment, authorized use only._`);
    out.push('');
    out.push('## Network picture');
    out.push('');
    out.push(this.mermaid());
    out.push('');
    out.push('## Nodes');
    out.push('');
    out.push('| Node | Version | Auth | Replica set | Databases (collection count) |');
    out.push('|------|---------|------|-------------|------------------------------|');
    for (const n of this.nodes.values()) {
      const dbs = Object.entries(n.databases || {})
        .map(([db, colls]) => `${db} (${Object.keys(colls).length})`).join(', ') || '—';
      const auth = n.authRequired === false ? 'none' : (n.accessCred ? `yes → cracked (${n.accessCred.user})` : 'yes');
      out.push(`| ${n.host}:${n.port} | ${n.version || '?'} | ${auth} | ${n.setName || '—'} | ${dbs} |`);
    }
    out.push('');
    out.push('## Harvested credentials');
    out.push('');
    if (this.credentials.length) {
      out.push('| User | Password | Scope | Found at |');
      out.push('|------|----------|-------|----------|');
      for (const c of this.credentials) out.push(`| ${c.user} | \`${c.pass}\` | ${c.scope} | ${c.foundAt} |`);
    } else out.push('_none_');
    out.push('');
    out.push('## Findings (most severe first)');
    out.push('');
    for (const f of findings) {
      out.push(`### [${f.severity}] ${f.title} — \`${f.nodeId}\``);
      out.push('');
      out.push(f.detail);
      out.push('');
      out.push(`**Remediation:** ${f.remediation}`);
      out.push('');
    }
    return out.join('\n');
  }
}
