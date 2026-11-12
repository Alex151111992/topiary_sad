import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createSiteServer } from './server.mjs';

const origin = 'https://shop.example.test';
// Synthetic credentials, used only with disposable test databases.
const password = 'A test phrase with spaces 2026';
const registration = { email: 'Person@example.test', password, confirmPassword: password };

function app(t, settings = {}, dependencies = {}) {
  const server = createSiteServer({ siteOrigin: origin, ...settings }, dependencies);
  let closing;
  function close() {
    if (!closing) closing = new Promise(resolve => {
      server.once('close', resolve);
      server.close();
    });
    return closing;
  }
  t.after(close);
  async function request(path, { method = 'GET', data, raw, headers = {}, chunks } = {}) {
    const body = raw ?? (data === undefined ? '' : JSON.stringify(data));
    const req = Readable.from(chunks ?? [Buffer.from(body)]);
    Object.assign(req, {
      url: path, method, socket: { remoteAddress: '127.0.0.1' },
      headers: { host: 'shop.example.test', origin, 'content-type': 'application/json', ...headers },
    });
    return new Promise(resolve => {
      const output = new Headers();
      let code = 200;
      server.emit('request', req, {
        setHeader(name, value) { output.set(name, value); },
        writeHead(status, extra = {}) {
          code = status;
          for (const [name, value] of Object.entries(extra)) output.set(name, value);
          return this;
        },
        end(value) { resolve(new Response(value, { status: code, headers: output })); },
      });
    });
  }
  const post = (path, data, headers) => request(path, { method: 'POST', data, headers });
  return { request, post, close };
}

test('регистрация, сессия после обновления, выход и повторный вход с новым cookie', async t => {
  const site = app(t);
  const registered = await site.post('/api/auth/register', registration);
  assert.equal(registered.status, 201);
  assert.deepEqual(await registered.json(), { authenticated: true, account: { email: 'person@example.test' } });
  const cookie = registered.headers.get('set-cookie');
  assert.match(cookie, /^__Host-topiary_session=.+; Path=\/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure$/);
  const headers = { cookie: cookie.split(';')[0] };
  const current = await (await site.request('/api/auth/session', { headers })).json();
  assert.deepEqual(current, { authenticated: true, providers: ['email'], account: { email: 'person@example.test' } });
  assert.equal((await (await site.request('/api/auth/session')).json()).authenticated, false);

  const logout = await site.post('/api/auth/logout', {}, headers);
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0; HttpOnly; SameSite=Lax; Secure/);
  assert.equal((await (await site.request('/api/auth/session', { headers })).json()).authenticated, false);
  const login = await site.post('/api/auth/login', { email: ' PERSON@example.test ', password });
  assert.equal(login.status, 200);
  assert.notEqual(login.headers.get('set-cookie'), cookie);
  assert.doesNotMatch(await login.text(), /password|salt|hash|session=/i);
});

test('аккаунты сохраняются после перезапуска, исходные пароли и сессии в базе отсутствуют', async t => {
  const folder = mkdtempSync(join(tmpdir(), 'topiary-auth-test-'));
  t.after(() => {
    const resolved = realpathSync(folder);
    assert.equal(dirname(resolved), realpathSync(tmpdir()));
    assert.ok(basename(resolved).startsWith('topiary-auth-test-'));
    rmSync(resolved, { recursive: true, force: true });
  });
  const accountFile = join(folder, 'accounts.sqlite');
  const first = app(t, { accountFile });
  const registered = await first.post('/api/auth/register', registration);
  const cookie = registered.headers.get('set-cookie').split(';')[0];
  assert.equal(registered.status, 201);
  const other = await first.post('/api/auth/register', { ...registration, email: 'other@example.test' });
  assert.equal(other.status, 201);
  await first.close();

  const db = new DatabaseSync(accountFile, { readOnly: true });
  const rows = db.prepare('SELECT salt, password_hash FROM accounts').all();
  db.close();
  assert.equal(rows.length, 2);
  assert.notEqual(rows[0].salt, rows[1].salt);
  assert.notEqual(rows[0].password_hash, rows[1].password_hash);
  assert.equal(rows[0].password_hash.length, 128);
  const bytes = readFileSync(accountFile);
  assert.equal(bytes.includes(Buffer.from(password)), false);
  assert.equal(bytes.includes(Buffer.from(cookie.split('=')[1])), false);

  const restarted = app(t, { accountFile });
  assert.equal((await (await restarted.request('/api/auth/session', { headers: { cookie } })).json()).authenticated, false);
  assert.equal((await restarted.post('/api/auth/login', { email: registration.email, password })).status, 200);
  await restarted.close();
});

test('повторная и одновременная регистрация почты не перезаписывает пароль', async t => {
  const site = app(t);
  const [a, b] = await Promise.all([
    site.post('/api/auth/register', registration),
    site.post('/api/auth/register', { ...registration, email: 'PERSON@example.test' }),
  ]);
  assert.deepEqual([a.status, b.status].sort(), [201, 409]);
  const replacement = { ...registration, password: 'Different test phrase 2026', confirmPassword: 'Different test phrase 2026' };
  assert.equal((await site.post('/api/auth/register', replacement)).status, 409);
  assert.equal((await site.post('/api/auth/login', { email: registration.email, password })).status, 200);
  const invalid = await site.post('/api/auth/login', { email: registration.email, password: replacement.password });
  const unknown = await site.post('/api/auth/login', { email: 'absent@example.test', password });
  assert.equal(invalid.status, 401);
  assert.equal(unknown.status, 401);
  assert.equal(await invalid.text(), await unknown.text());
  assert.equal(invalid.headers.get('set-cookie'), null);
});

test('сервер отклоняет неверные поля, короткий пароль и несовпадающее подтверждение', async t => {
  const site = app(t);
  for (const data of [
    {}, { ...registration, email: 'not-an-email' }, { ...registration, email: 'a..b@example.test' },
    { ...registration, email: 'a@-example.test' }, { ...registration, email: ['person@example.test'] },
    { ...registration, password: 'short' }, { ...registration, password: 'x'.repeat(129) },
    { ...registration, confirmPassword: 'wrong' }, { ...registration, password: null },
  ]) {
    const result = await site.post('/api/auth/register', data);
    assert.equal(result.status, 400);
    assert.equal(result.headers.get('set-cookie'), null);
  }
  const unicode = 'Мой длинный пароль с пробелами 🙂';
  assert.equal((await site.post('/api/auth/register', { email: 'unicode@example.test', password: unicode, confirmPassword: unicode })).status, 201);
  assert.equal((await site.post('/api/auth/login', { email: 'unicode@example.test', password: unicode })).status, 200);
});

test('CSRF, чужой Host, подмена forwarded-заголовков и неподходящий формат не проходят', async t => {
  const site = app(t);
  for (const path of ['/api/auth/register', '/api/auth/login', '/api/auth/logout']) {
    for (const headers of [
      { origin: 'https://evil.example' }, { origin: undefined }, { origin: 'null' },
      { host: 'evil.example' }, { 'sec-fetch-site': 'cross-site' },
      { origin: 'https://evil.example', 'x-forwarded-host': 'shop.example.test', 'x-forwarded-proto': 'https' },
    ]) assert.equal((await site.post(path, registration, headers)).status, 403);
    assert.equal((await site.request(path)).status, 405);
  }
  assert.equal((await site.post('/api/auth/register', registration, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await site.request('/api/auth/register', { method: 'POST', raw: '{broken' })).status, 400);
  assert.equal((await site.request('/api/auth/register', { method: 'POST', raw: '[]' })).status, 400);
  assert.equal((await site.request('/api/auth/register', { method: 'POST', raw: 'x'.repeat(5000) })).status, 413);
  assert.equal((await site.post('/api/auth/register', registration, { 'content-length': '5000' })).status, 413);
  for (const path of ['/accounts.mjs', '/accounts.sqlite', '/README.md', '/email-auth.test.mjs', '/../accounts.sqlite']) {
    assert.equal((await site.request(path)).status, 404);
  }
});

test('подбор ограничивается по адресу и почте, forwarded-заголовки не обходят лимит', async t => {
  const site = app(t);
  for (let i = 0; i < 10; i++) {
    assert.equal((await site.post('/api/auth/register', { ...registration, confirmPassword: 'wrong' })).status, 400);
  }
  const blocked = await site.post('/api/auth/login', registration);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('retry-after'), '900');
  for (let i = 11; i < 30; i++) assert.equal((await site.post('/api/auth/login', {})).status, 400);
  const byIp = await site.post('/api/auth/login', {}, { 'x-forwarded-for': '8.8.8.8' });
  assert.equal(byIp.status, 429);
});

test('VK и почта доступны вместе, выход завершает также VK-сессию', async t => {
  const site = app(t, { clientId: '12345', redirectUri: `${origin}/auth/vkid` }, {
    fetchVk: async url => Response.json({ state: url.searchParams.get('state'), access_token: 'test-token', user_id: 1 }),
  });
  assert.deepEqual((await (await site.request('/api/auth/session')).json()).providers, ['email', 'vk']);
  const emailSession = await site.post('/api/auth/register', registration);
  const emailCookie = emailSession.headers.get('set-cookie').split(';')[0];
  const start = await site.request('/api/auth/vk/start');
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const attempt = start.headers.get('set-cookie').split(';')[0];
  const vk = await site.request(`/auth/vkid?${new URLSearchParams({ state, code: 'test', device_id: 'test' })}`, {
    headers: { cookie: `${emailCookie}; ${attempt}` },
  });
  const cookie = vk.headers.get('set-cookie').split(';')[0];
  assert.equal((await (await site.request('/api/auth/session', { headers: { cookie: emailCookie } })).json()).authenticated, false);
  const vkSession = await (await site.request('/api/auth/session', { headers: { cookie } })).json();
  assert.equal(vkSession.authenticated, true);
  assert.equal(vkSession.account, undefined);
  assert.equal((await site.post('/api/auth/logout', {}, { cookie })).status, 200);
  assert.equal((await (await site.request('/api/auth/session', { headers: { cookie } })).json()).authenticated, false);
});

test('без настройки домена почта работает только через loopback, база запрещена в исходниках', async t => {
  assert.throws(() => createSiteServer({ siteOrigin: 'http://shop.example.test' }), /HTTPS/);
  assert.throws(() => createSiteServer({ siteOrigin: `${origin}/wrong` }), /SITE_ORIGIN/);
  assert.throws(() => createSiteServer({ siteOrigin: origin, clientId: '123', redirectUri: 'https://different.example/auth/vkid' }), /совпадать/);
  assert.throws(() => createSiteServer({ accountFile: fileURLToPath(new URL('./forbidden.sqlite', import.meta.url)) }), /вне папки/);
  const site = app(t, { siteOrigin: undefined });
  assert.equal((await site.post('/api/auth/register', registration)).status, 403);
  assert.equal((await site.post('/api/auth/register', registration, { host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' })).status, 201);
});

test('лимит двух вычислений пароля не допускает неограниченного расхода памяти', async t => {
  const site = app(t);
  const requests = [1, 2, 3].map(i => site.post('/api/auth/register', { ...registration, email: `parallel${i}@example.test` }));
  const results = await Promise.all(requests);
  assert.deepEqual(results.map(result => result.status).sort(), [201, 201, 503]);
});
