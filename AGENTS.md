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
- **Startup races the replica-set election (fixed 2026-10-19):** on the
  first-ever run, `seedDb`'s first write can land while `rs-edge` is still
  electing and die with `InterruptedDueToReplStateChange`, crashing lab
  startup. `seedDb` in `lab/lab.mjs` now retries transient replica-state
  errors with backoff — seeding is idempotent (delete-then-insert), so a
  whole-seed retry is safe. Do not remove the retry as "cleanup".
  The same fragility exists one step earlier: `MongoMemoryReplSet.create`
  waits a hard-coded 30s for a primary (no option to raise it), and on a
  slow or just-booted machine it throws `WaitForPrimaryTimeoutError`.
  `createReplSetWithRetry` in `lab/lab.mjs` retries the whole create up
  to 3 times; creation has no side effects until it succeeds.
- **Small `/tmp` breaks the lab (fixed 2026-10-19):**
  `mongodb-memory-server` puts each node's data dir under the system temp
  dir, four nodes total ~500 MB, and a crashed run leaves its `mongo-mem-*`
  dirs behind. On a machine where `/tmp` is a small tmpfs (512 MB in the
  test VM) the lab filled it on its own — the last `mongod` died with an
  opaque `fassert() failure`, and the orphans then broke every later run.
  `lab/lab.mjs` now defaults `TMPDIR` to a project-local `.tmp-lab/` dir
  (git-ignored) when the user has not set `TMPDIR` themselves, so the data
  lives on the project's disk. An explicit `TMPDIR` is always respected.
  If you hit the old failure mode on an unpatched checkout, delete stale
  `/tmp/mongo-mem-*` dirs and re-run.

## The app (production-app demo)
`npm run app` → http://127.0.0.1:8900 (`app/server.mjs` + `app/index.html`, zero extra deps). Streams a live lab assessment to the UI over SSE: the engine emits progress through an optional `onEvent` hook on ClusterGraph (`toolkit/lib/graph.mjs`) — off by default, CLI behavior unchanged. Two phases: `before` (one seed entry point, full pivot) and `after` (hardened cluster, port-scan discovery). Server allows one run at a time (409 while busy); targets are generated internally (the loopback lab only). Gotcha baked into the server: the SSE `done` event is sent only AFTER lab teardown completes — the client re-arms its buttons on `done`, so sending it earlier lets an immediate follow-up run hit the busy guard and stall.

## Data & structure inventory (added 2026-10-19)
`harvest()` in `toolkit/lib/enumerate.mjs` now returns, per collection: document count, `fields` (every field path with the BSON types seen, inferred client-side from the sampled docs), `indexes` (name + keys via listIndexes), and `sample` (one example document with secret-looking values redacted — the redaction pattern in enumerate.mjs is intentionally wider than the secrets scanner's, covering hash/pw-style field names). The inventory rides on the node record (`nodes[].databases[db][coll]`) into findings.json, the markdown report's "Data inventory" section, the HTML report's node view, and the app's click-a-node panel. Still read-only: sampling + listIndexes only.

## Download + dashboard (added 2026-10-19)
- **Download:** `Dockerfile` + `docker-compose.yml` = one-command local run (`docker compose up --build` → app on 8900). `scripts/warm-cache.mjs` pre-downloads the mongod binary at image build time so runtime needs no network. The app binds `HOST` env (default 127.0.0.1; compose sets 0.0.0.0 inside the container only). NOTE: no container runtime exists on the dev VM — the Dockerfile is written and reviewed but its build is verified by the user/CI, not here.
- **Dashboard:** `npm run dashboard` → http://127.0.0.1:8901 (`dashboard/server.mjs` + `index.html`). Ingest: `POST /api/ingest` with `Authorization: Bearer $DASHBOARD_TOKEN` (default `dev-token`). Runs stored as JSON under `dashboard/data/<estate>/` (gitignored).
- **Trust contract (do not weaken):** results leave the local app ONLY when the user presses send, after seeing the exact payload (`GET /api/last-run` preview). Passwords are redacted by the sender (`redactRun` in app/server.mjs) AND stripped again by the dashboard on ingest (`stripPasswords`). Stored dashboard files must never contain a raw password — verified by grep in the 2026-10-19 end-to-end test.
