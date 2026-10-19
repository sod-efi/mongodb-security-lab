// NODE B seed — runs authenticated as the root user (admin:admin, the weak
// default). Creates the read-only reporting user whose credentials are leaked
// on Node A, and seeds reporting data.
db = db.getSiblingDB('reporting');

db.createUser({
  user: 'report_ro',
  pwd: 'R3port!ng',
  roles: [{ role: 'read', db: 'reporting' }],
});

db.daily_metrics.insertMany([
  { day: '2026-01-30', signups: 42, revenue: 1890.5 },
  { day: '2026-01-31', signups: 51, revenue: 2210.0 },
]);
db.report_defs.insertMany([
  { id: 'r-weekly', owner: 'svc-admin', query: 'revenue by region' },
]);
