/*
 * Tiny default credential list for the "weak/default admin password" lesson.
 * These are the handful of defaults real scanners check first. Kept short on
 * purpose: this is a teaching lab, not a brute-force tool.
 */
export const DEFAULT_CREDS = [
  { user: 'admin', pass: 'admin', authSource: 'admin' },
  { user: 'root', pass: 'root', authSource: 'admin' },
  { user: 'admin', pass: 'password', authSource: 'admin' },
  { user: 'admin', pass: '', authSource: 'admin' },
  { user: 'mongo', pass: 'mongo', authSource: 'admin' },
];
