// NODE C seed — runs authenticated as root (whadmin). Holds the crown-jewel
// data. The whadmin password looks strong but is sitting in plaintext on Node
// A, so compromise of A leads straight here.
db = db.getSiblingDB('warehouse');

db.createUser({
  user: 'etl_svc',
  pwd: 'etl-pipeline-2024',
  roles: [{ role: 'readWrite', db: 'warehouse' }],
});

db.customers_pii.insertMany([
  { cid: 'C-001', name: 'Alice Customer', ssn_last4: '4821', dob: '1990-04-11', tier: 'gold' },
  { cid: 'C-002', name: 'Bob Customer', ssn_last4: '7734', dob: '1985-11-02', tier: 'silver' },
]);
db.payments.insertMany([
  { pid: 'P-9001', cid: 'C-001', pan_token: 'tok_****4242', amount: 129.99, status: 'captured' },
  { pid: 'P-9002', cid: 'C-002', pan_token: 'tok_****1111', amount: 59.0, status: 'refunded' },
]);
db.etl_secrets.insertMany([
  { name: 's3-export', access_key: 'AKIAFAKEKEY0LABONLY', note: 'nightly dump target' },
]);
