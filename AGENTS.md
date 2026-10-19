# AGENTS.md — mongodb-security-lab

The guide to read first when working in this repo.

## What it is

A **self-contained, authorized lab** that demonstrates how a single weak MongoDB
node becomes a foothold and how an assessor pivots across a cluster to
reconstruct the full network and database picture — then hardens it and proves
the fixes work. Built as a school keystone project.

**Ethics / scope:** everything is fictional and runs on localhost or a private
Docker network you own. The assessment tool is READ-ONLY and refuses any target
that is not loopback/RFC1918 unless `--authorized-external` is passed (only for
systems you own or are contracted in writing to test). Do not point it at
infrastructure you do not control.

## Where it runs / deploys

Runs locally only — there is nothing to deploy and no secrets. Requires Node.js
18+ (developed on Node 24). On first run `mongodb-memory-server-core` downloads
an official `mongod` binary (~600 MB, cached afterwards). Docker is optional (a
portable 3-node lab lives in `lab/docker-compose.yml`).

## How to run and test locally

```bash
npm install
npm run demo          # lab up, assess from one entry point, tear down
npm run demo:discover # same, but the tool port-scans to find the nodes itself
npm run demo:report   # assess vulnerable -> harden -> re-assess -> open report.html
npm run demo:learn    # run the same assessment 3x; self-improvement trend
npm run learn:reset   # wipe the learned knowledge store
npm run lab:up        # bring the lab up and leave it running
node toolkit/mongo-recon.mjs --discover 127.0.0.1 --ports 27017-27022 --lab
```

There is no automated test suite; verification is the demos above plus
`node --check` on each `.mjs`. `output/report.html` is the interactive report
(open in a browser). See `docs/README.md` for the full file map and
`docs/METHODOLOGY.md` for the attack chain.

## Conventions

- Read-only assessment: no writes, drops, config changes, DoS, or evasion.
- Scope is enforced in `toolkit/lib/safety.mjs` (loopback/RFC1918 + the Docker
  lab hostnames only).
- One source of truth for the lab topology: `lab/topology.mjs`.
- The engine is `toolkit/recon.mjs` (`assess()`); `toolkit/mongo-recon.mjs` is a
  thin CLI; `lab/lab.mjs` is the lab factory (vulnerable + hardened variants).
- Self-improvement is on by default; the learned store is `toolkit/.memory/`
  (git-ignored). Disable with `--no-learn`, wipe with `--reset-learning`.

## Gotchas learned

- **Two labs, two port ranges.** The before/after demo runs the vulnerable
  (27018-27021) and hardened (27030-27032) labs at the same time. Rebinding the
  same port right after teardown hits Windows TIME_WAIT, so `mongod` silently
  lands on a different port; always build the seed URI from `srv.getUri()`.
- **Replica set + auth in memory-server is flaky.** The no-Docker lab puts the
  replica set on the no-auth Node A (reliable) and uses standalone auth for B/C.
- **Findings must not depend on which credential won the access race.** The
  privilege picture is computed with the most-capable known credential, and the
  credential-reuse finding is based on what was found stored, not on the cred
  that enumerated the node. This keeps learning from changing results.
- **Phone-size screenshots:** the app's built-in browser renders local files as
  static snapshots (no JS); serve the report over a tiny HTTP server to view it.
