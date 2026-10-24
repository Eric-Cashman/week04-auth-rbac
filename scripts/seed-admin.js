'use strict';

// Creates (or promotes) the first Admin account from values in .env.
// Run with: npm run seed:admin

require('dotenv').config({ quiet: true });

const bcrypt = require('bcrypt');
const { statements } = require('../db');

const username = process.env.ADMIN_USERNAME;
const password = process.env.ADMIN_PASSWORD;

if (!username || !password) {
  console.error('Set ADMIN_USERNAME and ADMIN_PASSWORD in your .env file first.');
  process.exit(1);
}
if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
  console.error('ADMIN_USERNAME must be 3-32 characters: letters, numbers, . _ -');
  process.exit(1);
}
if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
  console.error('ADMIN_PASSWORD must be 12-72 characters.');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);
const existing = statements.findByUsername.get(username);

if (existing) {
  statements.setAdmin.run(hash, existing.id);
  console.log(`Existing user "${username}" updated and set to Admin.`);
} else {
  statements.insertUser.run(username, hash, 'Admin');
  console.log(`Admin user "${username}" created.`);
}
