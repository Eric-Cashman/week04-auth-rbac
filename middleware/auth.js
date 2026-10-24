'use strict';

const jwt = require('jsonwebtoken');
const { statements } = require('../db');

const COOKIE_NAME = 'token';
const TOKEN_LIFETIME = '1h';
const COOKIE_MAX_AGE_MS = 60 * 60 * 1000;

// No fallback value: the app must not run with a missing or weak secret.
function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      'JWT_SECRET must be set in .env and be at least 32 characters long'
    );
  }
  return secret;
}

function signToken(userId) {
  return jwt.sign({}, getSecret(), {
    algorithm: 'HS256',
    subject: String(userId),
    expiresIn: TOKEN_LIFETIME,
  });
}

function cookieOptions() {
  return {
    httpOnly: true, // not readable by JavaScript, which limits XSS token theft
    sameSite: 'strict', // not sent on cross-site requests, which limits CSRF
    secure: process.env.NODE_ENV === 'production', // HTTPS-only in production
    maxAge: COOKIE_MAX_AGE_MS,
  };
}

function clearCookieOptions() {
  const { maxAge, ...rest } = cookieOptions();
  return rest;
}

// Returns the current user from the cookie, or null. The role always comes
// from the database, never from the token, so it cannot be forged or go stale.
function getUserFromRequest(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (typeof token !== 'string' || token.length === 0) return null;

  let payload;
  try {
    payload = jwt.verify(token, getSecret(), { algorithms: ['HS256'] });
  } catch (err) {
    return null;
  }

  const id = Number(payload.sub);
  if (!Number.isInteger(id)) return null;

  return statements.findById.get(id) || null;
}

// Route guard 1: must be logged in, otherwise 401 Unauthorized.
function authenticate(req, res, next) {
  const user = getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  req.user = user;
  next();
}

// Route guard 2: must hold a specific role, otherwise 403 Forbidden.
// Always use after authenticate().
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (req.user.role !== role) {
      return res
        .status(403)
        .json({ error: 'Forbidden: insufficient permissions' });
    }
    next();
  };
}

module.exports = {
  COOKIE_NAME,
  getSecret,
  signToken,
  cookieOptions,
  clearCookieOptions,
  getUserFromRequest,
  authenticate,
  requireRole,
};
