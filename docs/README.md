# MongoDB cluster security lab — PoC

A **self-contained, authorized lab** that demonstrates how a single weak MongoDB
node becomes a foothold, and how an assessor pivots from it across a cluster to
reconstruct the full **network and database picture**.

It ships two things:

1. **A deliberately-vulnerable 3-node cluster** you stand up yourself.
2. **`mongo-recon`** — a read-only assessment tool that, given one entry point,
   fingerprints the node, gains access, harvests secrets out of the data, and
   pivots to every other node it can reach, then draws the whole map.

> ### ⚠️ Authorized lab use only
> Every host, credential and record in this project is fictional and runs on
> **your own machine (localhost / a private Docker network)**. The tool refuses
> any target that is not loopback/RFC1918 unless you pass `--authorized-external`,
> which you should use **only** against systems you own or are contracted to
> test in writing. Do not point this at infrastructure you do not control.

---

## The scenario (what you are meant to find)

```
   ENTRY                                            GOAL
   ┌───────────────┐  stored plaintext   ┌──────────────────┐
   │  NODE A        │  connection URIs    │  NODE C          │
   │  appdb         │ ──────────────────► │  warehouse       │
   │  NO AUTH       │                     │  customers_pii   │
   │  (foothold)    │                     │  payments        │
   └──────┬────────-┘                     └──────────────────┘
          │ replica-set hello leaks            ▲ reached with the
          │ a 2nd member (topology)            │ "strong" password
          ▼                                     │ that was leaked on A
   ┌───────────────┐                     ┌──────┴───────────┐
   │  NODE A'       │                     │  NODE B          │
   │  (replica)     │                     │  reporting       │
   │  NO AUTH       │                     │  admin:admin     │
   └───────────────┘                     └──────────────────┘
```

Five classes of weakness, each a real, common MongoDB mistake:

| # | Node | Weakness | Why it matters |
|---|------|----------|----------------|
| 1 | A | **No authentication** | Anyone who reaches the port reads/writes everything |
| 2 | A | **Replica-set topology disclosed pre-auth** | `hello` needs no auth and leaks internal member hosts |
| 3 | A | **Secrets stored in the database** | Plaintext downstream connection strings = a map + keys |
| 4 | B | **Default/weak admin password** (`admin:admin`) | Guessed in one try; grants admin |
| 5 | C | **Credential reuse** | The "strong" warehouse password was lying on Node A |

---

## Run it — no Docker needed (verified path)

Requires Node.js 18+. On first run it downloads an official `mongod` binary
(~600 MB, cached afterwards) and runs three real MongoDB processes on localhost.

```bash
npm install
npm run demo:report   # ★ runs the attack, then hardens the lab and re-runs,
                      #   and opens an interactive report that flips red -> green
npm run demo          # just the attack: lab up, assess, tear down
```

`demo:report` is the one to show: it assesses the vulnerable cluster, applies the
fixes (auth everywhere, strong unique passwords, secrets removed), re-assesses,
and opens `output/report.html` — a self-contained page with a **Before/After
toggle**, a clickable severity-coloured network graph, and a "fix this first"
banner. No internet or external libraries needed to view it.

### It gets better with use (self-improvement loop)

```bash
npm run demo:learn    # runs the same assessment 3x; watch the work drop
npm run learn:reset   # wipe what it learned (keeps one .bak)
```

Every assessment records which **credentials**, **ports**, and **collections**
actually produced hits, into a local store (`toolkit/.memory/`, git-ignored).
The next run reads that back and tries the proven ones first: it skips the
anonymous attempt on nodes known to require auth, tries each node's known-good
credential before guessing, and skips the default-password sweep on ports that
never accepted one. The **findings never change** — only the number of attempts
to reach them. A typical `demo:learn`:

| run | auth attempts | time to first finding | findings |
|-----|---------------|-----------------------|----------|
| 1   | 10            | ~24 ms                | 12 (5 critical) |
| 2   | 5             | ~17 ms                | 12 (5 critical) |
| 3   | 5             | ~18 ms                | 12 (5 critical) |

Learning is on by default for `assess`/`demo`; add `--no-learn` to disable, or
`--reset-learning` to start fresh.

Or drive it yourself:

```bash
npm run lab:up        # terminal 1: bring the lab up and leave it running
# terminal 2 — hand it one entry node:
node toolkit/mongo-recon.mjs --seed 127.0.0.1:27018 --lab
# or let it FIND the nodes itself by port-sweeping the lab:
node toolkit/mongo-recon.mjs --discover 127.0.0.1 --ports 27017-27022 --lab
```

`npm run demo:discover` runs the whole thing with **no seed** — the tool
discovers the nodes by connect-scanning the port range, then pivots from there.
`--discover` also accepts a small CIDR (e.g. `10.0.0.0/28`, /24../32 only).

Reports are written to `output/findings.json` and `output/network-map.md`.

## Run it — with Docker (portable path)

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml --profile tools run --rm recon
docker compose -f lab/docker-compose.yml down -v
```

The Docker lab uses three standalone nodes (A no-auth, B weak admin, C leaked
password). The replica-set topology-leak scenario (#2) is demonstrated by the
no-Docker runner, which starts Node A as a real 2-member replica set.

---

## Project layout

```
lab/
  topology.mjs          single source of truth: nodes, creds, seed data
  lab.mjs               lab factory: vulnerable + hardened variants
  start-lab.mjs         no-Docker runner (real mongod via memory-server)
  demo-report.mjs       before/after orchestrator -> interactive HTML report
  docker-compose.yml    portable 3-node lab + in-network recon runner
  docker-init/*.js      seed scripts for the Docker lab
  demo-learn.mjs        self-improvement demo (same assessment, 3x)
toolkit/
  mongo-recon.mjs       the assessment CLI (thin wrapper)
  recon.mjs             the assessment engine (BFS pivot + learning), importable
  reset-learning.mjs    wipe the knowledge store
  lib/
    safety.mjs          target-scope guardrails (lab/private only)
    discover.mjs        scope-guarded TCP connect-scan (finds seed nodes)
    enumerate.mjs       read-only fingerprint + enumerate a single node
    secrets.mjs         find mongodb:// URIs & secrets, parse them
    graph.mjs           accumulate the cluster, render JSON + Mermaid report
    report-html.mjs     self-contained interactive HTML report (before/after)
    memory.mjs          self-improvement knowledge store (rank + record)
    wordlist.mjs        tiny default-credential list
  .memory/              learned knowledge (git-ignored)
output/                 generated reports (git-ignored)
  report.html           interactive report (open in a browser)
docs/
  README.md             this file
  METHODOLOGY.md        the attack chain mapped to MITRE ATT&CK, step by step
  REPORT.md             an example findings report (the gradeable write-up)
```

## What the tool does — and does not — do

- **Does:** optionally TCP connect-scan a lab host/CIDR to find nodes, then
  connect, `hello`/`buildInfo`, `listDatabases`/`listCollections`,
  `connectionStatus`, `usersInfo`, sample a few documents, parse secrets, try a
  short default-credential list, and follow discovered hosts/creds. All reads.
- **Does not:** write, drop, modify data or server config, run denial-of-service,
  evade detection, or touch anything outside loopback/private ranges.

See [METHODOLOGY.md](METHODOLOGY.md) for the full walk-through and
[REPORT.md](REPORT.md) for an example findings write-up with remediation.
