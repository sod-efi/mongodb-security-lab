# memory.md — standing decisions for mongodb-security-lab

- 2026-10-19: Lab-only, read-only, authorized-use-only PoC (school keystone). The
  assessment tool refuses non-loopback/RFC1918 targets unless `--authorized-external`.
- 2026-10-19: Built in Node (not Python) because Node is on PATH on the dev PC
  and the no-Docker lab uses `mongodb-memory-server-core` (Node).
- 2026-10-19: The before/after demo runs the vulnerable (27018-27021) and
  hardened (27030-27032) labs at the same time on different ports, to avoid
  Windows TIME_WAIT when rebinding a just-released port.
- 2026-10-19: Findings must be independent of which credential won the access
  race — the privilege picture uses the most-capable known credential and
  credential-reuse is based on stored creds. This lets the self-improvement loop
  reorder probes without changing results.
- 2026-10-19: Self-improvement is on by default; learned store is `toolkit/.memory/`
  (git-ignored). Measured effect on this lab: auth attempts ~10 → 5, findings
  unchanged (12, 5 critical).
