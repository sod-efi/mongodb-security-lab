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

## Command line

```bash
npm run demo           # one seed → whole cluster (nodes, creds, findings, report)
npm run demo:discover  # no seed — the port scanner finds the nodes itself
npm run demo:report    # vulnerable vs hardened, static interactive report.html
npm run demo:learn     # self-improvement loop: repeated runs, fewer wasted probes
```
