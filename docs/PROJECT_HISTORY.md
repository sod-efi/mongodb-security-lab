# Project history

## 2026-10-19 — Initial build

Built a self-contained, lab-only MongoDB security PoC for a school keystone
project. Goal: from one entry point, find vulnerabilities in a MongoDB node and
pivot across the cluster to reconstruct the full network and database picture —
then prove the fixes.

**Vulnerable lab** (`lab/`). Three nodes, two ways to run:
- No-Docker runner (`lab/start-lab.mjs`, `lab/lab.mjs`) using real `mongod` via
  `mongodb-memory-server-core`; and a portable `lab/docker-compose.yml`.
- Node A: no auth, a 2-member replica set, stores plaintext downstream
  connection strings. Node B: auth with weak default `admin:admin`. Node C:
  auth whose "strong" password is the one leaked on A; holds PII/payments.

**Assessment tool** (`toolkit/`). Read-only, scope-guarded. Fingerprints a node,
gains access (anonymous / harvested / default creds), harvests secrets from the
data, and pivots breadth-first. Outputs `findings.json`, a Mermaid
`network-map.md`, and an interactive `report.html`.

**Discovery.** Added a scope-guarded TCP connect-scan (`toolkit/lib/discover.mjs`)
so the tool finds its own seed nodes (`--discover host|CIDR --ports a-b`),
refusing public hosts and CIDRs larger than /24.

**Interactive report + harden-and-rescan.** `lab/demo-report.mjs` assesses the
vulnerable cluster, boots a hardened variant, re-assesses, and builds a
self-contained `report.html` whose Before/After toggle flips the map from red
(5 critical) to green (0). Verified visually.

**Self-improvement loop.** Every run records which credentials, ports, and
collections produced hits (`toolkit/lib/memory.mjs`, store in `toolkit/.memory/`,
git-ignored). The next run tries proven options first: skips the anonymous
attempt on auth nodes, tries each node's known-good credential first, and skips
the default-password sweep on ports that never accepted one. Measured: auth
attempts drop ~10 → 5 across repeated runs while findings stay identical (12,
5 critical), confirmed by a learning-off vs learning-on diff. `npm run demo:learn`
shows the trend; `npm run learn:reset` undoes it.

### Open items

- No automated test suite (verification is the demos + `node --check`).
- The Docker lab is standalone 3-node; the replica-set topology-leak scenario is
  demonstrated by the no-Docker runner. Could unify with a keyfile-based Docker
  replica set.
- Learning ranks per-port; could generalise across similar services.

### Ideas discussed but not built

- Detection-evasion / offensive payloads — deliberately excluded (lab teaches
  discovery, exploitation of misconfig, and remediation, not evasion).
- A nmap/Scapy-based scanner — kept it a pure-Node TCP connect-scan for
  portability and to avoid native dependencies.
