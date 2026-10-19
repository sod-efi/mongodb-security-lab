# mongodb-security-lab

MongoDB security assessment tool: vulnerable cluster, recon + lateral movement, interactive report, self-improvement loop.

## The app — start here

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

## Command line

```bash
npm run demo           # one seed → whole cluster (nodes, creds, findings, report)
npm run demo:discover  # no seed — the port scanner finds the nodes itself
npm run demo:report    # vulnerable vs hardened, static interactive report.html
npm run demo:learn     # self-improvement loop: repeated runs, fewer wasted probes
```
