# Methodology — one node to the whole cluster

This is the assessment methodology `mongo-recon` automates, written out so the
project stands on its own as a keystone artefact. It is a defensive exercise:
the goal is to **demonstrate and then fix** the weaknesses, so each phase ends
with the detection/remediation angle.

The phases follow the familiar kill-chain shape and map to MITRE ATT&CK
techniques so the work is anchored to a recognised framework.

---

## Phase 0 — Scope & authorisation

Before anything runs, the operator fixes the scope. In this tool that is
enforced in code (`toolkit/lib/safety.mjs`): targets must be loopback or RFC1918
private, or the explicit Docker lab hostnames. Real engagements add written
authorisation, a target list, and rules of engagement. **Scope is a control, not
a formality** — it is what separates an assessment from an intrusion.

## Phase 1a — Discover reachable nodes (optional)
*ATT&CK: T1046 Network Service Discovery, T1595 Active Scanning*

If no entry point is handed in, the tool port-sweeps a lab host or small CIDR
(`--discover 127.0.0.1 --ports 27017-27021`). It is a plain TCP connect-scan: no
raw packets, bounded concurrency, and **every host is scope-checked before a
single connection**, with a 256-host cap so it cannot become a mass scan. Open
ports become the seed nodes for everything below.

> *Fix:* MongoDB ports should not be reachable from general networks at all —
> segment them, bind to private interfaces, and alert on connection-scan patterns
> (many short-lived connects across a port range from one source).

## Phase 1 — Fingerprint the entry node
*ATT&CK: T1046 Network Service Discovery, T1590 Gather Victim Network Info*

Given one reachable node, the tool opens a **direct** connection and runs the
`hello` (formerly `isMaster`) handshake. This requires **no authentication** and
tells you:

- the server version (`buildInfo`, also pre-auth),
- whether access control is enabled (inferred from whether `listDatabases`
  is rejected as unauthorised),
- and, crucially, **replica-set membership**: `setName` and the `hosts` array.

> **Finding #2 lives here.** On a replica set, `hello` hands an unauthenticated
> caller the internal host:port of every member. That is a free network map.
> *Fix:* keep the port off untrusted networks; require TLS with client-certs so
> an unknown peer cannot complete the handshake.

## Phase 2 — Gain read access
*ATT&CK: T1190 Exploit Public-Facing Application, T1078 Valid Accounts,
T1110 Brute Force (default-credential check)*

The tool attempts, in order:

1. **Anonymous** access. If `listDatabases` succeeds with no credentials, access
   control is simply off. **Finding #1** — the single most common MongoDB
   breach cause (thousands of open instances have been wiped historically).
2. **Harvested credentials** carried over from earlier nodes (see Phase 4).
3. A short **default-credential** list (`admin:admin`, `root:root`, …).

Independently, on any auth-enabled node it probes the default list and records a
hit even if it already got in another way — so **Finding #4** (Node B accepts
`admin:admin`) is reported whether or not a harvested cred was tried first.

> *Fix:* `security.authorization: enabled`; delete default accounts; strong,
> unique, rotated passwords; prefer SCRAM-SHA-256 or x.509; alert on logins with
> default usernames.

## Phase 3 — Understand the principal
*ATT&CK: T1087 Account Discovery, T1069 Permission Groups Discovery*

With a session, `connectionStatus { showPrivileges: true }` says **who you are
and what you can do**, and `usersInfo` (when permitted) lists **every user on the
node**. A read-only app user that can also enumerate the user catalogue is an
over-privilege finding in its own right (**Finding, HIGH**).

> *Fix:* application users get the minimum role on the minimum database; `userAdmin`
> / `viewUser` stay with dedicated admin principals only.

## Phase 4 — Harvest secrets from the data itself
*ATT&CK: T1552 Unsecured Credentials, T1213 Data from Information Repositories*

This is the hinge of the whole exercise. The tool samples documents and scans
them (recursively) for:

- `mongodb://user:pass@host/…` **connection strings**, and
- fields whose names look like secrets (`password`, `token`, `apiKey`,
  `access_key`, `uri`, …).

Applications routinely store downstream connection strings in a `config` or
`service_connections` collection. Reading one node therefore yields **both a map
of the next nodes and the keys to them**. **Finding #3.**

> *Fix:* secrets never live in application collections. Use a secrets manager
> (Vault, cloud secret store), inject at runtime, scrub existing documents, and
> rotate everything that was exposed.

## Phase 5 — Pivot (lateral movement)
*ATT&CK: T1021 Remote Services, T1550 Use of Alternate Authentication Material*

Every host discovered in Phase 1 (replica-set members) and every host parsed out
of a harvested URI in Phase 4 is pushed onto a **breadth-first queue**, carrying
any credentials found with it. The engine then repeats Phases 1–4 on each, so:

- a harvested read-only cred opens **Node B**,
- the leaked "strong" warehouse password opens **Node C** as `root` — **Finding #5,
  credential reuse**, the step that reaches the crown-jewel PII and payment data,
- and the replica-set `hello` on **Node A** surfaces its second member, which the
  queue then visits too.

> *Fix:* unique credentials per service so one leak does not cascade; network
> segmentation between tiers; monitor for a single principal authenticating to
> many hosts in a short window.

## Phase 6 — Build the picture (collection & reporting)
*ATT&CK: T1119 Automated Collection*

The accumulated graph — nodes (version, auth posture, replica set, databases),
edges (how each was reached), harvested credentials, and findings — is written to:

- `output/findings.json` — machine-readable, the full picture, and
- `output/network-map.md` — a **Mermaid diagram** of nodes and pivot edges, a
  node/database table, the harvested-credential table, and the findings ranked
  by severity.

That network-and-database picture, reached from a single entry point, is the
deliverable the exercise is built to produce.

## Phase 7 — Learn from the run (self-improvement)

Every run writes what it learned to a small local store: which credentials
authenticated on which ports, which ports hosted a node, and which collection
names held secrets. The next run reads it back and **reorders its probes** so
the proven options come first:

- it skips the anonymous attempt on ports known to require authentication,
- it tries a node's previously-successful credential before anything else,
- it skips the default-password sweep on ports that never accepted one, and
- it samples secret-bearing collection names first.

This is a complete loop: capture (per-run signals) -> learn (ranked store) ->
apply (reordered probes next run) -> measure (authentication attempts and
time-to-first-finding, recorded each run). On this lab the attempts roughly
halve after the first run while the **findings stay identical** — the privilege
picture is always computed with the most-capable credential known for a node, so
learning changes only the path, never the result. Undo with `npm run learn:reset`.
`npm run demo:learn` runs the same assessment three times and prints the trend.

---

## Detection notes (blue-team view)

Each offensive step has a cheap detector, which is the point of running this in a
lab:

| Step | What a defender would see / should alert on |
|------|---------------------------------------------|
| Phase 1a | many short-lived TCP connects across a port range from one source (connection-scan) |
| Phase 1 | `hello`/`isMaster` from unexpected source IPs; replica-set ports reachable off the management network |
| Phase 2 | auth failures for default usernames; **any** successful anonymous command on a server that should require auth |
| Phase 3 | `usersInfo` / `connectionStatus … showPrivileges` by an application principal |
| Phase 4 | large `find` sweeps over `config`/`service_connections`-style collections |
| Phase 5 | one credential authenticating across several hosts in minutes; logins from a tier that should not talk to another tier |

Enable MongoDB auditing (`auditLog`), ship logs centrally, and baseline which
principals touch which databases from which hosts.
