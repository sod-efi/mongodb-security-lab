# Example findings report — MongoDB cluster assessment

> Example write-up produced from one run of this lab. It is the kind of report
> the exercise is meant to generate; adapt the wording for your submission. The
> machine-readable version is `output/findings.json`; the auto-generated map is
> `output/network-map.md`.

**Engagement type:** authorised internal lab assessment
**Scope:** `127.0.0.1:27018` as the only known entry point (lab, loopback-only)
**Method:** read-only enumeration + credential-based lateral movement
**Result:** full compromise of a 4-instance cluster from a single foothold;
sensitive customer PII and payment records reached.

---

## 1. Executive summary

Starting from one unauthenticated MongoDB node, the assessment reached every
node in the environment and read its most sensitive data within seconds. The
root causes are ordinary misconfigurations: an exposed node with authentication
disabled, downstream credentials stored in plaintext inside the database, a
default administrative password, and reuse of a "strong" password that was
itself exposed. None required an exploit or a zero-day — only reachability and
configuration mistakes.

**Impact:** read access to `customers_pii` (names, DOB, SSN-last-4) and
`payments` on the warehouse node; full administrative control of two of four
instances; a complete internal topology map.

**Overall risk: CRITICAL.**

## 2. Attack path

```
seed → 127.0.0.1:27018 (appdb, NO AUTH)
          ├─ harvested conn-string → 127.0.0.1:27019 (reporting; also accepts admin:admin)
          ├─ harvested conn-string → 127.0.0.1:27020 (warehouse; root via leaked pw)  ◄ crown jewels
          └─ replica-set member    → 127.0.0.1:27021 (appdb replica, NO AUTH)
```

## 3. Findings

### [CRITICAL] F-1 Unauthenticated database access — `127.0.0.1:27018` (and `:27021`)
The node accepts anonymous connections and exposes `appdb` (users, sessions, and
a service-configuration collection) with no authentication. Anyone able to reach
the port has full read, and by default write, access.
**Evidence:** `listDatabases` and collection reads succeeded with no credentials.
**Remediation:** set `security.authorization: enabled`; create least-privilege
users; bind to private interfaces and firewall the port.

### [CRITICAL] F-2 Secrets stored in application data → full pivot — `127.0.0.1:27018`
`appdb.service_connections` stores plaintext `mongodb://` URIs for the reporting
and warehouse nodes, **including their credentials**. This single collection
provided both the location of the other nodes and the keys to them.
**Evidence:** two connection URIs harvested; credentials `report_ro` and
`whadmin` extracted.
**Remediation:** remove secrets from the database; use a secrets manager; scrub
and rotate all exposed credentials.

### [CRITICAL] F-3 Default administrative credential — `127.0.0.1:27019`
The reporting node authenticates `admin:admin`, a well-known default, granting
administrative control.
**Evidence:** default-credential probe authenticated `admin:admin`.
**Remediation:** remove default accounts; strong unique password; SCRAM-SHA-256
or x.509; alert on default-username logins.

### [CRITICAL] F-4 Credential reuse reaches crown jewels — `127.0.0.1:27020`
The warehouse node enforces authentication with a strong-looking password, but
that exact password was stored in plaintext on Node A. Using it gave `root`, and
with it the `customers_pii`, `payments`, and `etl_secrets` collections.
**Evidence:** authenticated as `whadmin` (root@admin) with the harvested
password; read customer PII and payment records.
**Remediation:** unique credentials per service; network segmentation between
tiers; rotate the exposed password immediately.

### [MEDIUM] F-5 Replica-set topology disclosed pre-authentication — `127.0.0.1:27018`
The unauthenticated `hello` handshake disclosed replica set `rs-edge` and the
host:port of a second member, which was then reachable and equally unauthenticated.
**Evidence:** `hello.setName = rs-edge`, `hosts = [127.0.0.1:27018, 127.0.0.1:27021]`.
**Remediation:** keep replica-set traffic on a private network; restrict who can
reach the port; TLS with client-certificate authentication.

### [HIGH] F-6 Over-privileged principal can read the user catalogue — `127.0.0.1:27020`
The session could enumerate all database users via `usersInfo`.
**Remediation:** restrict `userAdmin`/`viewUser` to dedicated admin principals.

## 4. Remediation priority

1. **Enable authentication everywhere and firewall the ports** (fixes F-1, F-5).
2. **Pull secrets out of the database and rotate them** (fixes F-2, and defuses F-4).
3. **Replace default/weak and reused passwords** (fixes F-3, F-4).
4. **Right-size roles** (fixes F-6).
5. **Turn on auditing** and alert on the patterns in METHODOLOGY.md.

## 5. How to reproduce

```bash
npm install && npm run demo
# then read output/network-map.md and output/findings.json
```
