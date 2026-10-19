// NODE A seed — runs with NO auth. Foothold node.
// Stores plaintext downstream connection strings (the pivot material).
db = db.getSiblingDB('appdb');

db.app_users.insertMany([
  { username: 'alice', email: 'alice@acme.test', pw_bcrypt: '$2b$10$Vd9Qe...redacted', role: 'customer' },
  { username: 'bob', email: 'bob@acme.test', pw_bcrypt: '$2b$10$8kLm2...redacted', role: 'customer' },
  { username: 'svc-admin', email: 'ops@acme.test', pw_bcrypt: '$2b$10$aa11...redacted', role: 'admin' },
]);

db.service_connections.insertMany([
  {
    name: 'reporting-db',
    note: 'read-only reporting user, points at the reporting node',
    uri: 'mongodb://report_ro:R3port!ng@node-b-reporting:27017/reporting?authSource=reporting',
  },
  {
    name: 'warehouse-admin',
    note: 'nightly ETL admin -- full access to the warehouse',
    uri: 'mongodb://whadmin:W4reh0use#2024-Str0ng@node-c-warehouse:27017/?authSource=admin',
  },
]);

db.sessions.insertMany([
  { sid: 's-1001', user: 'alice', ip: '203.0.113.10', ts: '2026-02-01T09:12:00Z' },
  { sid: 's-1002', user: 'bob', ip: '203.0.113.44', ts: '2026-02-01T10:03:00Z' },
]);
