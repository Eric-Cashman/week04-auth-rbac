(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const output = $('output');
  const sessionEl = $('session');

  // textContent only (never innerHTML), so server data can never inject markup.
  function show(label, data) {
    const body = data === null ? '(no JSON body)' : JSON.stringify(data, null, 2);
    output.textContent = `${label}\n\n${body}`;
  }

  function setSession(user) {
    sessionEl.textContent = user
      ? `Signed in as ${user.username} (${user.role})`
      : 'Not signed in';
  }

  async function api(method, url, body) {
    try {
      const options = { method, credentials: 'same-origin' };
      if (body !== undefined) {
        options.headers = { 'Content-Type': 'application/json' };
        options.body = JSON.stringify(body);
      }
      const res = await fetch(url, options);
      let data = null;
      try {
        data = await res.json();
      } catch (err) {
        data = null;
      }
      show(`${method} ${url} -> HTTP ${res.status} ${res.statusText}`.trim(), data);
      return { res, data };
    } catch (err) {
      output.textContent = 'Network error: could not reach the server.';
      return null;
    }
  }

  function readCredentials() {
    const username = $('username').value;
    const password = $('password').value;
    if (!$('skipChecks').checked && (username.trim() === '' || password === '')) {
      output.textContent = 'Client-side check: username and password are required.';
      return null;
    }
    return { username, password };
  }

  async function refreshSession() {
    try {
      const res = await fetch('/api/session', { credentials: 'same-origin' });
      const data = await res.json();
      setSession(data.authenticated ? data.user : null);
    } catch (err) {
      sessionEl.textContent = 'Could not check session';
    }
  }

  $('registerBtn').addEventListener('click', async () => {
    const creds = readCredentials();
    if (!creds) return;
    await api('POST', '/api/register', creds);
  });

  $('loginBtn').addEventListener('click', async () => {
    const creds = readCredentials();
    if (!creds) return;
    const result = await api('POST', '/api/login', creds);
    if (result && result.res.ok) {
      setSession(result.data.user);
      $('password').value = '';
    }
  });

  $('logoutBtn').addEventListener('click', async () => {
    const result = await api('POST', '/api/logout');
    if (result && result.res.ok) setSession(null);
  });

  $('publicBtn').addEventListener('click', () => api('GET', '/api/public'));
  $('profileBtn').addEventListener('click', () => api('GET', '/api/profile'));
  $('adminBtn').addEventListener('click', () => api('GET', '/api/admin/users'));

  refreshSession();
})();
