import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { createSiteServer } from './server.mjs';

const callbackPath = '/api/auth/vk/callback';
const config = { clientId: '12345', redirectUri: `https://shop.example.test${callbackPath}` };

function site(t, { configured = true, exchangeResponse, settings = config } = {}) {
  const exchanges = [];
  let time = Date.now();
  const server = createSiteServer(configured ? settings : {}, {
    now: () => time,
    fetchVk: async (url, options) => {
      exchanges.push({ url, options });
      if (exchangeResponse) return exchangeResponse(url);
      return Response.json({
        state: url.searchParams.get('state'),
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        user_id: 123,
      });
    },
  });
  t.after(() => server.close());

  function get(path, cookie, host = new URL(settings.redirectUri).host) {
    return new Promise(resolve => {
      const request = { url: path, method: 'GET', headers: { cookie, host } };
      const headers = new Headers();
      let status = 200;
      const response = {
        setHeader: (name, value) => headers.set(name, value),
        writeHead(code, extraHeaders = {}) {
          status = code;
          for (const [name, value] of Object.entries(extraHeaders)) headers.set(name, value);
          return this;
        },
        end(body) {
          resolve(new Response(body, { status, headers }));
        },
      };
      server.emit('request', request, response);
    });
  }

  async function start(cookie) {
    const response = await get('/api/auth/vk/start', cookie);
    const authorization = new URL(response.headers.get('location'));
    const setCookie = response.headers.get('set-cookie');
    const state = authorization.searchParams.get('state');
    return { authorization, state, setCookie, cookie: setCookie.split(';')[0] };
  }

  function callback(attempt, params = { code: 'test-code', device_id: 'test-device' }, cookie = attempt.cookie) {
    const query = new URLSearchParams({ state: attempt.state, ...params });
    return get(`${new URL(settings.redirectUri).pathname}?${query}`, cookie);
  }

  return { get, start, callback, exchanges, tick: milliseconds => { time += milliseconds; } };
}

test('витрина доступна без настроек VK ID, а исходники сервера закрыты', async t => {
  const app = site(t, { configured: false });
  const page = await app.get('/');
  assert.match(await page.text(), /Войти через VK ID/);
  assert.equal((await app.get('/auth.js')).status, 200);
  assert.equal((await app.get('/server.mjs')).status, 404);
  assert.equal((await app.get('/server.test.mjs')).status, 404);
  assert.deepEqual(await (await app.get('/api/auth/session')).json(), { authenticated: false, providers: [] });
  const start = await app.get('/api/auth/vk/start');
  assert.equal(start.headers.get('location'), '/?login=unconfigured#login');
  assert.equal(start.headers.get('set-cookie'), null);
  assert.equal(app.exchanges.length, 0);
});

test('обмен кода VK ID создаёт отдельную сессию, токены не возвращаются клиенту', async t => {
  const app = site(t);
  const attempt = await app.start();
  const params = attempt.authorization.searchParams;
  assert.equal(attempt.authorization.origin, 'https://id.vk.ru');
  assert.equal(attempt.authorization.pathname, '/authorize');
  assert.equal(params.get('response_type'), 'code');
  assert.equal(params.get('client_id'), config.clientId);
  assert.equal(params.get('redirect_uri'), config.redirectUri);
  assert.equal(params.get('code_challenge_method'), 's256');
  assert.match(attempt.state, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(params.has('code_verifier'), false);
  assert.match(attempt.setCookie, /^__Host-topiary_vk_attempt=.+; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/);

  const response = await app.callback(attempt);
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), '/#login');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  const setCookie = response.headers.get('set-cookie');
  assert.match(setCookie, /^__Host-topiary_session=.+; Path=\/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure$/);
  assert.doesNotMatch(setCookie, /test-access-token|test-refresh-token/);
  assert.equal(await response.text(), '');

  assert.equal(app.exchanges.length, 1);
  const [{ url, options }] = app.exchanges;
  assert.equal(url.origin, attempt.authorization.origin);
  assert.equal(url.pathname, '/oauth2/auth');
  assert.equal(url.searchParams.get('grant_type'), 'authorization_code');
  assert.equal(url.searchParams.get('device_id'), 'test-device');
  assert.equal(url.searchParams.get('redirect_uri'), config.redirectUri);
  assert.equal(url.searchParams.get('client_id'), config.clientId);
  assert.equal(url.searchParams.get('state'), attempt.state);
  assert.equal(url.searchParams.has('code'), false);
  const verifier = url.searchParams.get('code_verifier');
  assert.equal(createHash('sha256').update(verifier).digest('base64url'), params.get('code_challenge'));
  assert.equal(options.method, 'POST');
  assert.equal(options.body.get('code'), 'test-code');
  assert.equal(options.redirect, 'error');

  const sessionCookie = setCookie.split(';')[0];
  const session = await app.get('/api/auth/session', sessionCookie);
  assert.equal(session.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await session.json(), { authenticated: true, providers: ['vk'] });
  assert.equal((await (await app.get('/api/auth/session')).json()).authenticated, false);
  app.tick(3600000);
  assert.equal((await (await app.get('/api/auth/session', sessionCookie)).json()).authenticated, false);
});

test('зарегистрированный адрес /auth/vkid обменивает код и создаёт сессию', async t => {
  const settings = { clientId: '54889426', redirectUri: 'https://www.topiary-sad.ru/auth/vkid' };
  const app = site(t, { settings });
  const attempt = await app.start();
  assert.equal(attempt.authorization.searchParams.get('client_id'), settings.clientId);
  assert.equal(attempt.authorization.searchParams.get('redirect_uri'), settings.redirectUri);
  assert.equal((await app.callback({ ...attempt, state: 'wrong' })).headers.get('location'), '/?login=error#login');
  assert.equal((await app.callback(attempt, undefined, '')).headers.get('location'), '/?login=error#login');

  const response = await app.callback(attempt);
  assert.equal(response.headers.get('location'), '/#login');
  assert.equal(app.exchanges[0].url.searchParams.get('redirect_uri'), settings.redirectUri);
  const cookie = response.headers.get('set-cookie').split(';')[0];
  assert.equal((await (await app.get('/api/auth/session', cookie)).json()).authenticated, true);
  assert.equal((await app.callback(attempt)).headers.get('location'), '/?login=error#login');
  assert.equal(app.exchanges.length, 1);
  assert.equal((await app.get(`${callbackPath}?state=${attempt.state}`, attempt.cookie)).status, 404);
});

test('вход с другого домена переходит на www до создания cookie попытки', async t => {
  const settings = { clientId: '54889426', redirectUri: 'https://www.topiary-sad.ru/auth/vkid' };
  const app = site(t, { settings });
  const response = await app.get('/api/auth/vk/start', undefined, 'topiary-sad.ru');
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('location'), 'https://www.topiary-sad.ru/api/auth/vk/start');
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(app.exchanges.length, 0);
  assert.equal((await app.start()).authorization.origin, 'https://id.vk.ru');

  const foreign = await app.get('/?next=https://foreign.example/', undefined, 'foreign.example');
  assert.equal(new URL(foreign.headers.get('location')).origin, 'https://www.topiary-sad.ru');
  const missing = await app.get('/', undefined, '');
  assert.equal(missing.headers.get('location'), 'https://www.topiary-sad.ru/');
});

test('callback без правильного state или cookie отклоняется', async t => {
  const app = site(t);
  const attempt = await app.start();
  const wrongState = await app.callback({ ...attempt, state: 'wrong' });
  const noCookie = await app.callback(attempt, undefined, '');
  const duplicateState = await app.get(`${callbackPath}?state=${attempt.state}&state=${attempt.state}`, attempt.cookie);
  for (const response of [wrongState, noCookie, duplicateState]) {
    assert.equal(response.headers.get('location'), '/?login=error#login');
    assert.equal(response.headers.get('set-cookie'), null);
  }
  assert.equal(app.exchanges.length, 0);
  assert.equal((await app.callback(attempt)).headers.get('location'), '/#login');
});

test('повторный и одновременный callback не обменивают код повторно', async t => {
  const app = site(t);
  const attempt = await app.start();
  const responses = await Promise.all([app.callback(attempt), app.callback(attempt)]);
  assert.deepEqual(responses.map(response => response.headers.get('location')).sort(), ['/#login', '/?login=error#login']);
  assert.equal((await app.callback(attempt)).headers.get('location'), '/?login=error#login');
  assert.equal(app.exchanges.length, 1);
});

test('отмена и ошибка VK не создают сессию и не раскрывают описание провайдера', async t => {
  const app = site(t);
  const attempt = await app.start();
  const cancelled = await app.callback(attempt, { error: 'access_denied' });
  assert.equal(cancelled.headers.get('location'), '/?login=cancelled#login');
  assert.equal(cancelled.headers.get('set-cookie'), null);
  assert.equal((await app.callback(attempt)).headers.get('location'), '/?login=error#login');

  const failed = await app.callback(await app.start(), { error: 'server_error', error_description: 'private detail' });
  assert.equal(failed.headers.get('location'), '/?login=error#login');
  assert.equal(await failed.text(), '');
  assert.equal(app.exchanges.length, 0);
});

test('callback без device_id или с повтором code не отправляется в VK', async t => {
  const app = site(t);
  const missing = await app.callback(await app.start(), { code: 'test-code' });
  const attempt = await app.start();
  const duplicate = await app.get(`${callbackPath}?state=${attempt.state}&device_id=device&code=a&code=b`, attempt.cookie);
  assert.equal(missing.headers.get('location'), '/?login=error#login');
  assert.equal(duplicate.headers.get('location'), '/?login=error#login');
  assert.equal(app.exchanges.length, 0);
});

test('новый запуск заменяет предыдущую попытку, просроченная попытка отклоняется', async t => {
  const app = site(t);
  const previous = await app.start();
  const current = await app.start(previous.cookie);
  assert.notEqual(current.state, previous.state);
  assert.equal((await app.callback(previous)).headers.get('location'), '/?login=error#login');
  app.tick(600000);
  assert.equal((await app.callback(current)).headers.get('location'), '/?login=error#login');
  assert.equal(app.exchanges.length, 0);
});

const rejectedExchanges = new Map([
  ['неуспешный HTTP-ответ', () => new Response(null, { status: 503 })],
  ['ошибка OAuth с HTTP 200', () => Response.json({ error: 'invalid_grant' })],
  ['некорректный JSON', () => new Response('not json')],
  ['несовпадение state', () => Response.json({ state: 'wrong', access_token: 'test-token', user_id: 123 })],
  ['отсутствие токена', url => Response.json({ state: url.searchParams.get('state'), user_id: 123 })],
  ['отсутствие пользователя', url => Response.json({ state: url.searchParams.get('state'), access_token: 'test-token' })],
  ['сетевая ошибка', () => { throw new Error('provider unavailable'); }],
]);

for (const [name, exchangeResponse] of rejectedExchanges) {
  test(`ответ VK не создаёт сессию: ${name}`, async t => {
    const app = site(t, { exchangeResponse });
    const response = await app.callback(await app.start());
    assert.equal(response.headers.get('location'), '/?login=error#login');
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(app.exchanges.length, 1);
  });
}

test('неполная конфигурация и небезопасный внешний адрес отклоняются', () => {
  assert.throws(() => createSiteServer({ clientId: config.clientId }), /VK_REDIRECT_URI/);
  assert.throws(() => createSiteServer({ ...config, redirectUri: `http://shop.example.test${callbackPath}` }), /HTTPS/);
  assert.throws(() => createSiteServer({ ...config, redirectUri: `${config.redirectUri}?query=value` }), /VK_REDIRECT_URI/);
  assert.throws(() => createSiteServer({ ...config, redirectUri: 'https://shop.example.test/unknown' }), /VK_REDIRECT_URI/);
});
