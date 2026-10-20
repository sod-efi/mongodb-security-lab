# mongodb-security-lab

MongoDB security assessment tool: vulnerable cluster, recon + lateral movement, interactive report, self-improvement loop.

## The app — start here

One-command download (everything runs on your machine; the scanner makes
no outbound calls at runtime):

```bash
docker compose up --build    # → http://127.0.0.1:8900
```

or without Docker:

```bash
npm install && npm run app
```

Open http://127.0.0.1:8900 and press **Run live assessment**. The demo
cluster gives the tool a single entry point; you watch the full network
and database picture build itself live — nodes appear on the graph as
they are discovered, findings stream in as they are proven, credentials
land as they are harvested. When it finishes, **Apply hardening &
re-scan** runs the same scanner against the hardened cluster and the
picture flips green.

Then switch to the **Assess my own cluster** tab: give it one node of a
cluster you own (or pick port-scan), optionally a credential, and it
reconstructs your cluster the same way. Loopback/private targets only,
unless you explicitly confirm authorization for an external one — the
scope check runs on every node it pivots to, and credentials are held
in memory for the run only.

**Hosted demo:** https://mongodb-security-lab-production.up.railway.app
— the demo cluster only (own-cluster mode is disabled there by design;
download the app to scan your own systems).

## The dashboard (optional cloud layer)

```bash
npm run dashboard            # → http://127.0.0.1:8901
```

After a scan in the app, **Send this result to my dashboard** shows you
the exact payload first — passwords are stripped before sending, and the
dashboard strips them again on arrival. The dashboard keeps every run:
fleet view across estates, critical-findings trend, and a diff between
consecutive scans (what got fixed, what appeared). Results only — the
scanner itself never leaves your network.
Hosted: https://mongodb-security-dashboard-production.up.railway.app
(token-gated ingest; run history kept on a persistent volume).

**Drift agent:** `agent/agent.mjs` closes the loop — it re-scans your
clusters on a schedule and sends each result to the dashboard, so drift
surfaces itself instead of waiting for someone to remember to scan.

```bash
cp agent/config.example.json agent/config.json   # your targets + dashboard
npm run agent            # loop on the configured interval
npm run agent -- --once  # single pass (cron/systemd friendly)
```

Each pass logs one line per target with the drift vs the last run
(`critical 5 → 0 · findings +1 / −12`). Credentials in the config are
used only to authenticate to your own nodes; results are redacted
before they leave the machine, same contract as the app.

## License

The scanner, app, agent, toolkit, and lab are licensed under the
**Business Source License 1.1** (see `LICENSE`): free to run in
production against MongoDB systems you own or are authorized in
writing to assess — read every line before you run it, that's the
point — but you may not offer it to third parties as a hosted or
subscription service or ship it in a competing product. On
October 20, 2030 each version converts to the Apache License 2.0.

The **dashboard** is proprietary (`dashboard/LICENSE`): its code is
here so the ingest contract can be audited, and the hosted service is
operated by us.

## Command line

```bash
npm run demo           # one seed → whole cluster (nodes, creds, findings, report)
npm run demo:discover  # no seed — the port scanner finds the nodes itself
npm run demo:report    # vulnerable vs hardened, static interactive report.html
npm run demo:learn     # self-improvement loop: repeated runs, fewer wasted probes
```
