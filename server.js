'use strict';

require('dotenv').config({ quiet: true });

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');

const { statements } = require('./db');
const {
  COOKIE_NAME,
  getSecret,
  signToken,
  cookieOptions,
  clearCookieOptions,
  getUserFromRequest,
  authenticate,
  requireRole,
} = require('./middleware/auth');

getSecret(); // fail fast if JWT_SECRET is missing or weak

const BCRYPT_COST = 12;
// Compared against when the username does not exist, so a wrong username and a
// wrong password take about the same time (limits timing-based enumeration).
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_COST);
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const GENERIC_LOGIN_ERROR = 'Invalid username or password';

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function validateRegistration(body) {
  const { username, password } = body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return 'Username and password are required';
  }
  if (!USERNAME_RE.test(username)) {
    return 'Username must be 3-32 characters: letters, numbers, dot, underscore or hyphen';
  }
  // bcrypt only uses the first 72 bytes, so reject longer passwords.
  if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
    return 'Password must be 8-72 characters';
  }
  return null;
}

// ---------- Public ----------
app.get('/api/public', (req, res) => {
  res.json({ message: 'Public endpoint: anyone can read this.' });
});

// Lets the frontend ask "am I logged in?" without producing a 401 in the console.
app.get('/api/session', (req, res) => {
  const user = getUserFromRequest(req);
  res.json(user ? { authenticated: true, user } : { authenticated: false });
});

// ---------- Authentication ----------
app.post('/api/register', async (req, res, next) => {
  try {
    const error = validateRegistration(req.body);
    if (error) return res.status(400).json({ error });

    const { username, password } = req.body;
    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    try {
      // The role is fixed to 'User'. Any "role" field in the request is ignored.
      const info = statements.insertUser.run(username, passwordHash, 'User');
      return res.status(201).json({
        message: 'Registration successful',
        user: { id: Number(info.lastInsertRowid), username, role: 'User' },
      });
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'Username is not available' });
      }
      throw err;
    }
  } catch (err) {
    next(err);
  }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};
    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      username.length === 0 ||
      password.length === 0
    ) {
      return res
        .status(400)
        .json({ error: 'Username and password are required' });
    }

    const user = statements.findByUsername.get(username);
    const hashToCheck = user ? user.password_hash : DUMMY_HASH;
    const passwordOk = await bcrypt.compare(password, hashToCheck);

    // Same message and status whether the user is missing or the password is wrong.
    if (!user || !passwordOk) {
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR });
    }

    res.cookie(COOKIE_NAME, signToken(user.id), cookieOptions());
    return res.json({
      message: 'Login successful',
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, clearCookieOptions());
  res.json({ message: 'Logged out' });
});

// ---------- Protected (any authenticated user) ----------
app.get('/api/profile', authenticate, (req, res) => {
  res.json({ user: req.user });
});

// ---------- Restricted (Admin only) ----------
app.get('/api/admin/users', authenticate, requireRole('Admin'), (req, res) => {
  res.json({ users: statements.listUsers.all() });
});

// ---------- Fallbacks ----------
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Generic error handler: details go to the server log only, never to the client.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed JSON' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const port = Number(process.env.PORT) || 3000;
const host = process.env.HOST || '127.0.0.1';
app.listen(port, host, () => {
  console.log(`Server running at http://${host}:${port}`);
});
