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

Runs locally; two Railway deployments exist for the hosted demo and the dashboard (see the sections at the end of this file). No secrets in the repo — the dashboard ingest token lives in Railway variables. Requires Node.js
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
- **Download:** `Dockerfile` + `docker-compose.yml` = one-command local run (`docker compose up --build` → app on 8900). `scripts/warm-cache.mjs` pre-downloads the mongod binary at image build time so runtime needs no network. The app binds `HOST` env (default 127.0.0.1; compose sets 0.0.0.0 inside the container only). No container runtime exists on the dev VM — the image build is verified by deploying it on Railway (which caught the missing libcurl/libssl/lzma libs on the first attempt; see the Docker gotcha below).
- **Dashboard:** `npm run dashboard` → http://127.0.0.1:8901 (`dashboard/server.mjs` + `index.html`). Ingest: `POST /api/ingest` with `Authorization: Bearer $DASHBOARD_TOKEN` (default `dev-token`). Runs stored as JSON under `dashboard/data/<estate>/` (gitignored).
- **Trust contract (do not weaken):** results leave the local app ONLY when the user presses send, after seeing the exact payload (`GET /api/last-run` preview). Passwords are redacted by the sender (`redactRun` in `toolkit/lib/redact.mjs`) AND stripped again by the dashboard on ingest (`stripPasswords`). Stored dashboard files must never contain a raw password — verified by grep in the 2026-10-19 end-to-end test.

## Own-cluster mode + hosted demo (added 2026-10-19)
- The app has two tabs: **Demo cluster** and **Assess my own cluster** (seed-pivot or port-scan start, optional operator credential, authorization checkbox for external targets). Flow: UI POSTs to `/api/own-run/start` (credentials in the POST body, never a URL; scope pre-checked with `assertInScope`), gets a one-time id, then opens the SSE stream `/api/run?own=<id>`. Credentials live only in a server memory map, deleted when the run starts; nothing is persisted.
- `DEMO_ONLY=1` disables own-cluster mode server-side (403) and hides the tab. Any public deployment MUST set it — otherwise the hosted instance becomes a scanner strangers can aim.
- **Hosted demo (Railway):** project `mongodb-security-lab` (cdd8fd33-007e-413b-bf73-4154f43dbde0), service ee4ceff8-aefb-4aa8-9803-60b03de2f103, https://mongodb-security-lab-production.up.railway.app — built BY Railway from the repo Dockerfile, `DEMO_ONLY=1` set. Deploy from the staging copy `~/workspace/.mongo-railway-stage/` (repo stays clean); `railway up -y -d --service ee4ceff8-...` from there.
- **Docker gotcha (found by the first Railway build, 2026-10-19):** `node:24-bookworm-slim` lacks `libcurl.so.4`/`libssl3`/`liblzma5`, which the Ubuntu mongod binary links — the lab's mongod dies on start without them. The Dockerfile installs all three; the image's `warm-cache` step doubles as a smoke test that mongod can actually start, so a regression fails the build, not the user.

## Drift agent + hosted dashboard (added 2026-10-19)
- `redactRun` lives in `toolkit/lib/redact.mjs`, shared by the app server and the agent — one implementation of the trust contract, not two.
- `agent/agent.mjs`: config-driven (`agent/config.json`, gitignored; `AGENT_CONFIG` env override; token via config or `DASHBOARD_TOKEN` env). Loop mode on `intervalSeconds`, or `--once`. One log line per target with drift vs the agent's local `.state.json` (finding keys = severity|title|nodeId). The DASHBOARD diff is the estate-level record; the agent's state is per-target and local.
- **Lab auth-settle gate (`lab/lab.mjs`):** mongodb-memory-server nodes answer connections slightly before auth is enforced; an assessment in that window sees an auth node as wide open (observed: Node C reported unauthenticated, 11 findings/6 critical instead of 12/5). `startLab` now polls until auth nodes REFUSE anonymous listDatabases (and the foothold accepts), ~45s cap with a loud warning. Do not remove — every demo/agent number depends on it.
- **Hosted dashboard (Railway):** project `mongodb-security-dashboard` (2d2cd8e1-65f5-4a42-9157-9ff34e40c465), service 0e2b2309-9578-48ec-8fa7-7da7e44e14a3, https://mongodb-security-dashboard-production.up.railway.app — built from `dashboard/Dockerfile` (copied to the staging root), volume mounted at `/data` with `DASH_DATA_DIR=/data`, ingest token in the service's Railway variables (rotate it there; never in the repo). Deploy from `~/workspace/.mongo-dash-stage/` (refresh its contents from the repo first — a stale stage cost a debugging round).
- **Railway port rule (both services):** Railway routes traffic to its injected `$PORT`. Servers must prefer `PORT` over any app-specific default (dashboard: `DASH_PORT || PORT || 8901`). Pinning a fixed port variable (DASH_PORT) breaks routing with a 502 while the container looks perfectly healthy — the tell is a boot line naming a port Railway didn't assign.

## Licensing (decided 2026-10-19, by Ben)
- Scanner/app/agent/toolkit/lab: **BSL 1.1** (root `LICENSE`) — Additional Use Grant permits production use on systems the user owns or is authorized in writing to assess; prohibits hosted/subscription resale and competing products. Change Date Oct 20, 2030 → Apache 2.0. Licensor name is "SaveOnDev" (one-line change if Ben picks another entity).
- **Dashboard is proprietary** (`dashboard/LICENSE`) — excluded from the Licensed Work in the root LICENSE's scope note; code stays in the repo for audit of the ingest contract only. Never describe the dashboard as BSL/open.
- The repo is still PRIVATE; flipping visibility is Ben's manual GitHub step (the connector token has no Administration permission), to do when outreach starts.
