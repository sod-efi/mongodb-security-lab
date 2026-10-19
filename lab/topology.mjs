/*
 * Shared, single-source-of-truth definition of the intentionally-vulnerable
 * lab cluster. Both the Docker lab and the no-Docker Node runner build the
 * SAME topology, users and seed data from this file so findings are identical.
 *
 * === AUTHORIZED LAB USE ONLY ===
 * Every host/credential below is fictional and belongs to a cluster you stand
 * up yourself on localhost. Nothing here targets real infrastructure.
 *
 * The chain this models (a classic real-world MongoDB breach pattern):
 *   NODE A  exposed with NO AUTH  -> attacker reads everything, including an
 *           app "service connections" collection that stores plaintext
 *           connection URIs (with embedded credentials) for B and C.
 *   NODE B  auth enabled but WEAK default admin password (admin/admin), and it
 *           is a replica set, so hello/isMaster leaks internal member hostnames
 *           -> network map grows.
 *   NODE C  auth enabled with a "strong" password -> but that exact password
 *           was sitting in plaintext on Node A, so it falls anyway. Holds the
 *           crown-jewel PII/payment data.
 */

export const LAB_PORTS = { A: 27018, A2: 27021, B: 27019, C: 27020 };

// Credentials used across the lab. Deliberately weak / leaked to teach the point.
export const CREDS = {
  // Node B: classic default admin:admin (guessable), plus a read-only reporting user.
  B_admin: { user: 'admin', pwd: 'admin', db: 'admin', roles: ['root'] },
  B_report: { user: 'report_ro', pwd: 'R3port!ng', db: 'reporting', roles: ['read'] },
  // Node C: a "strong looking" admin password -- but it is leaked on Node A.
  C_admin: { user: 'whadmin', pwd: 'W4reh0use#2024-Str0ng', db: 'admin', roles: ['root'] },
  C_etl: { user: 'etl_svc', pwd: 'etl-pipeline-2024', db: 'warehouse', roles: ['readWrite'] },
};

// Human-readable node metadata (used for Docker service names / docs).
export const NODES = {
  A: { name: 'node-a-appdb', role: 'Public app node + exposed replica set (foothold)', auth: false, replSet: 'rs-edge' },
  B: { name: 'node-b-reporting', role: 'Reporting node (weak default admin)', auth: true, replSet: null },
  C: { name: 'node-c-warehouse', role: 'Data warehouse (crown jewels)', auth: true, replSet: null },
};

/*
 * Seed data per node. `hosts` in the URIs below use Docker service names; the
 * no-Docker runner rewrites them to 127.0.0.1:<port> at seed time so the same
 * "leaked credentials" are discoverable in both modes.
 */
export function seedData({ mode }) {
  const host = (svc, port) =>
    mode === 'docker' ? `${svc}:27017` : `127.0.0.1:${port}`;

  return {
    // ---- NODE A : no auth, the foothold -------------------------------------
    A: {
      appdb: {
        app_users: [
          { username: 'alice', email: 'alice@acme.test', pw_bcrypt: '$2b$10$Vd9Qe...redacted', role: 'customer' },
          { username: 'bob', email: 'bob@acme.test', pw_bcrypt: '$2b$10$8kLm2...redacted', role: 'customer' },
          { username: 'svc-admin', email: 'ops@acme.test', pw_bcrypt: '$2b$10$aa11...redacted', role: 'admin' },
        ],
        // THE PIVOT GOLD: plaintext downstream connection strings.
        service_connections: [
          {
            name: 'reporting-db',
            note: 'read-only reporting user, points at the reporting node',
            uri: `mongodb://${CREDS.B_report.user}:${CREDS.B_report.pwd}@${host('node-b-reporting', LAB_PORTS.B)}/reporting?authSource=reporting`,
          },
          {
            name: 'warehouse-admin',
            note: 'nightly ETL admin -- full access to the warehouse',
            uri: `mongodb://${CREDS.C_admin.user}:${CREDS.C_admin.pwd}@${host('node-c-warehouse', LAB_PORTS.C)}/?authSource=admin`,
          },
        ],
        sessions: [
          { sid: 's-1001', user: 'alice', ip: '203.0.113.10', ts: '2026-02-01T09:12:00Z' },
          { sid: 's-1002', user: 'bob', ip: '203.0.113.44', ts: '2026-02-01T10:03:00Z' },
        ],
      },
    },

    // ---- NODE B : weak admin + replica set topology leak --------------------
    B: {
      reporting: {
        daily_metrics: [
          { day: '2026-01-30', signups: 42, revenue: 1890.5 },
          { day: '2026-01-31', signups: 51, revenue: 2210.0 },
        ],
        report_defs: [
          { id: 'r-weekly', owner: 'svc-admin', query: 'revenue by region' },
        ],
      },
    },

    // ---- NODE C : crown jewels ---------------------------------------------
    C: {
      warehouse: {
        customers_pii: [
          { cid: 'C-001', name: 'Alice Customer', ssn_last4: '4821', dob: '1990-04-11', tier: 'gold' },
          { cid: 'C-002', name: 'Bob Customer', ssn_last4: '7734', dob: '1985-11-02', tier: 'silver' },
        ],
        payments: [
          { pid: 'P-9001', cid: 'C-001', pan_token: 'tok_****4242', amount: 129.99, status: 'captured' },
          { pid: 'P-9002', cid: 'C-002', pan_token: 'tok_****1111', amount: 59.0, status: 'refunded' },
        ],
        etl_secrets: [
          { name: 's3-export', access_key: 'AKIAFAKEKEY0LABONLY', note: 'nightly dump target' },
        ],
      },
    },
  };
}
