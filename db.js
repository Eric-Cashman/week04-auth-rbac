'use strict';

const path = require('path');
const Database = require('better-sqlite3');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.db');
const db = new Database(dbPath);

db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'User' CHECK (role IN ('User', 'Admin')),
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

// Every query is a prepared statement with bound parameters (never string concatenation).
const statements = {
  findByUsername: db.prepare(
    'SELECT id, username, password_hash, role FROM users WHERE username = ?'
  ),
  findById: db.prepare(
    'SELECT id, username, role, created_at FROM users WHERE id = ?'
  ),
  insertUser: db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  ),
  listUsers: db.prepare(
    'SELECT id, username, role, created_at FROM users ORDER BY id'
  ),
  setAdmin: db.prepare(
    "UPDATE users SET password_hash = ?, role = 'Admin' WHERE id = ?"
  ),
};

module.exports = { db, statements };
