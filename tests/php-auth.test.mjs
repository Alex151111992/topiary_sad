import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const php = process.env.PHP_BINARY || 'php';
const password = 'Local test phrase with spaces 2026';
const registration = { email: 'Person@example.test', password, confirmPassword: password };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('PHP: регистрация и вход через настоящее HTTP-соединение', async t => {
  const folder = mkdtempSync(join(tmpdir(), 'topiary-php-test-'));
  const dbPath = join(folder, 'accounts.sqlite');
  const listener = createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const args = ['-n', '-d', 'display_errors=0'];
  if (process.platform === 'win32') args.push('-d', `extension_dir=${join(dirname(php), 'ext')}`, '-d', 'extension=pdo_sqlite');
  args.push('-S', `127.0.0.1:${port}`, '-t', root, join(root, 'tests/php-router.php'));
  let child;
  let errors = '';
  async function start(siteOrigin = origin) {
    child = spawn(php, args, { cwd: root, windowsHide: true, env: { ...process.env, SITE_ORIGIN: siteOrigin, AUTH_DB_PATH: dbPath } });
    child.stderr.on('data', chunk => { errors = (errors + chunk.toString()).slice(-5000); });
    let launchError;
    child.on('error', error => { launchError = error; });
    for (let i = 0; i < 50; i++) {
      if (launchError) throw launchError;
      if (child.exitCode !== null) throw new Error(`PHP exited: ${errors}`);
      try { const response = await fetch(`${origin}/api/auth/session`, { redirect: 'manual' }); if ([200, 303].includes(response.status)) return; } catch {}
      await sleep(100);
    }
    throw new Error(`PHP did not start: ${errors}`);
  }
  async function stop() {
    if (child && child.exitCode === null) {
      await new Promise(resolve => { child.once('exit', resolve); child.kill(); });
    }
  }
  t.after(async () => {
    await stop();
    const resolved = realpathSync(folder);
    assert.equal(dirname(resolved), realpathSync(tmpdir()));
    assert.ok(basename(resolved).startsWith('topiary-php-test-'));
    rmSync(resolved, { recursive: true, force: true });
  });
  await start();
  const get = (path, headers = {}) => fetch(origin + path, { headers, redirect: 'manual' });
  const post = (path, body, headers = {}) => fetch(origin + path, {
    method: 'POST', redirect: 'manual', headers: { Origin: origin, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
  });
  let cookie;
  await t.test('провайдеры VK и почта, формы и публичные ресурсы', async () => {
    assert.deepEqual(await (await get('/api/auth/session')).json(), { authenticated: false, providers: ['email', 'vk'] });
    const page = await (await get('/')).text();
    assert.match(page, /id="email-register"/);
    assert.match(page, /id="catalog-grid"/);
    assert.equal((page.match(/id="login-status"/g) || []).length, 1);
    assert.equal((await get('/vk-id/auth.js')).status, 200);
    assert.equal((await get('/auth.css')).status, 200);
  });
  await t.test('валидация полей и совпадение паролей', async () => {
    for (const fields of [{ email: 'invalid' }, { password: 'short' }, { password: 'x'.repeat(129) }, { confirmPassword: 'different' }]) {
      assert.equal((await post('/api/auth/register', { ...registration, ...fields })).status, 400);
    }
  });
  await t.test('регистрация, защищённый cookie и состояние входа', async () => {
    const response = await post('/api/auth/register', registration);
    assert.equal(response.status, 201);
    assert.deepEqual(await response.json(), { authenticated: true, account: { email: 'person@example.test' } });
    assert.match(response.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
    cookie = response.headers.get('set-cookie').split(';')[0];
    const session = await (await get('/api/auth/session', { Cookie: cookie })).json();
    assert.equal(session.authenticated, true);
    assert.deepEqual(session.account, { email: 'person@example.test' });
    assert.equal((await (await get('/api/auth/session')).json()).authenticated, false);
  });
  await t.test('повторная регистрация не перезаписывает пароль', async () => {
    assert.equal((await post('/api/auth/register', { ...registration, email: 'PERSON@example.test' })).status, 409);
  });
  await t.test('чужой Origin, подмена Host и forwarded-заголовков, формат и размер', async () => {
    for (const path of ['/api/auth/register', '/api/auth/login', '/api/auth/logout']) {
      assert.equal((await post(path, registration, { Origin: 'https://evil.example', 'X-Forwarded-Host': '127.0.0.1' })).status, 403);
      assert.equal((await post(path, registration, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
      assert.equal((await get(path)).status, 405);
    }
    assert.equal((await post('/api/auth/register', registration, { 'Content-Type': 'text/plain' })).status, 415);
    assert.equal((await post('/api/auth/register', { value: 'x'.repeat(5000) })).status, 413);
    assert.equal((await post('/api/auth/register', [])).status, 400);
  });
  await t.test('ошибка входа одинаковая для отсутствующей почты и неверного пароля', async () => {
    const wrong = await post('/api/auth/login', { email: registration.email, password: 'Wrong test phrase with spaces' });
    const unknown = await post('/api/auth/login', { email: 'absent@example.test', password });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(await wrong.text(), await unknown.text());
    assert.equal(wrong.headers.get('set-cookie'), null);
  });
  await t.test('новый вход заменяет сессию, выход отменяет cookie на сервере', async () => {
    const login = await post('/api/auth/login', { email: ' PERSON@example.test ', password }, { Cookie: cookie });
    assert.equal(login.status, 200);
    const replacement = login.headers.get('set-cookie').split(';')[0];
    assert.notEqual(replacement, cookie);
    assert.equal((await (await get('/api/auth/session', { Cookie: cookie })).json()).authenticated, false);
    const logout = await post('/api/auth/logout', {}, { Cookie: replacement });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
    assert.equal((await (await get('/api/auth/session', { Cookie: replacement })).json()).authenticated, false);
  });
  await t.test('пароль не сохраняется открыто, аккаунт переживает перезапуск PHP', async () => {
    assert.equal(readFileSync(dbPath).includes(Buffer.from(password)), false);
    await stop();
    await start();
    assert.equal((await post('/api/auth/login', { email: registration.email, password })).status, 200);
  });
  await t.test('файлы базы и служебный код закрыты в тестовом маршрутизаторе', async () => {
    for (const path of ['/accounts.sqlite', '/email-auth.php', '/server.mjs', '/.env', '/tests/php-router.php']) {
      assert.equal((await get(path)).status, 404);
    }
  });
  await t.test('возврат без state не создаёт VK-сессию, PKCE и правильный callback сохранены', async () => {
    const start = await get('/api/auth/vk/start');
    const target = new URL(start.headers.get('location'));
    assert.equal(target.origin, 'https://id.vk.ru');
    assert.equal(target.searchParams.get('code_challenge_method'), 's256');
    const attemptCookie = start.headers.get('set-cookie').split(';')[0];
    const failed = await get('/api/auth/vk/callback?code=test&device_id=test', { Cookie: attemptCookie });
    assert.equal(failed.status, 303);
    assert.equal(failed.headers.get('location'), '/?login=error#login');
    assert.equal(failed.headers.get('set-cookie'), null);
    assert.equal((await get('/auth/vkid')).status, 404);
  });
  await t.test('лимит почты сохраняется между PHP-запросами и не обходится forwarded IP', async () => {
    // A fresh email avoids attempts already consumed by the earlier account tests.
    const body = { ...registration, email: 'limit@example.test', confirmPassword: 'different' };
    let limited;
    for (let i = 0; i < 11; i++) limited = await post('/api/auth/register', body, { 'X-Forwarded-For': `8.8.8.${i}` });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '900');
    const db = new DatabaseSync(dbPath);
    db.prepare('UPDATE email_rates SET expires_at = 0').run();
    db.close();
    assert.equal((await post('/api/auth/login', { email: registration.email, password })).status, 200);
  });
  await t.test('HTTPS-конфигурация ставит Secure cookie и переводит другой Host до создания сессии', async () => {
    await stop();
    await start('https://www.topiary-sad.ru');
    const canonical = await get('/api/auth/vk/start');
    assert.equal(canonical.status, 303);
    assert.equal(canonical.headers.get('location'), 'https://www.topiary-sad.ru/#login');
    assert.equal(canonical.headers.get('set-cookie'), null);
    const body = JSON.stringify({ ...registration, email: 'secure@example.test' });
    const response = await new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: '127.0.0.1', port, path: '/api/auth/register', method: 'POST', headers: {
        Host: 'www.topiary-sad.ru', Origin: 'https://www.topiary-sad.ru', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
      } }, res => {
        res.resume();
        res.on('end', () => resolve({ status: res.statusCode, cookie: res.headers['set-cookie']?.[0] }));
      });
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(response.status, 201);
    assert.match(response.cookie, /^__Host-topiary_session=.+; Path=\/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure$/);
  });
});
