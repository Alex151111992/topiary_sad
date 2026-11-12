import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { defaultAccountFile, normalizeEmail, openAccounts, validPassword } from './accounts.mjs';

const VK_ORIGIN = 'https://id.vk.ru';
const CALLBACK_PATHS = new Set(['/api/auth/vk/callback', '/auth/vkid']);
const ATTEMPT_SECONDS = 600;
const SESSION_SECONDS = 3600;
const STORE_LIMIT = 2048;
const RATE_SECONDS = 900;
const POST_PATHS = new Set(['/api/auth/register', '/api/auth/login', '/api/auth/logout']);

const assets = new Map([
  ['/', ['index.html', 'text/html']],
  ['/index.html', ['index.html', 'text/html']],
  ['/style.css', ['style.css', 'text/css']],
  ['/script.js', ['script.js', 'text/javascript']],
  ['/auth.js', ['auth.js', 'text/javascript']],
]);

function readVkConfig(clientId, redirectUri) {
  if (!clientId && !redirectUri) return null;
  if (!/^[1-9]\d*$/.test(clientId ?? '') || !redirectUri) {
    throw new Error('Укажите VK_CLIENT_ID и VK_REDIRECT_URI.');
  }

  const callback = new URL(redirectUri);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(callback.hostname);
  const validScheme = callback.protocol === 'https:' || (callback.protocol === 'http:' && loopback);
  if (!validScheme || !CALLBACK_PATHS.has(callback.pathname) || callback.username || callback.password || /[?#]/.test(redirectUri)) {
    throw new Error('VK_REDIRECT_URI должен вести на /auth/vkid или /api/auth/vk/callback по HTTPS. HTTP допустим только для локального адреса.');
  }
  return {
    clientId,
    redirectUri,
    callbackPath: callback.pathname,
    origin: callback.origin,
    host: callback.host,
    secure: callback.protocol === 'https:',
  };
}

function randomId() {
  return randomBytes(32).toString('base64url');
}

function readCookie(request, name) {
  const entry = request.headers.cookie?.split(';').map(cookie => cookie.trim())
    .find(cookie => cookie.startsWith(`${name}=`));
  const value = entry?.slice(name.length + 1);
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}

function writeCookie(response, name, id, seconds, secure) {
  response.setHeader('Set-Cookie', `${name}=${id}; Path=/; Max-Age=${seconds}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`);
}

function redirect(response, location) {
  response.writeHead(303, { Location: location }).end();
}

function singleParam(params, key) {
  const values = params.getAll(key);
  return values.length === 1 ? values[0] : null;
}

export function createSiteServer({ clientId, redirectUri, siteOrigin, accountFile = ':memory:' } = {}, { fetchVk = fetch, now = Date.now } = {}) {
  const vk = readVkConfig(clientId, redirectUri);
  const origin = siteOrigin ? new URL(siteOrigin) : vk ? new URL(vk.origin) : null;
  if (origin && ((siteOrigin && origin.origin !== siteOrigin) || origin.pathname !== '/' || origin.search || origin.hash ||
      origin.username || origin.password || (origin.protocol !== 'https:' &&
      !(origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname))))) {
    throw new Error('SITE_ORIGIN должен быть HTTPS-адресом сайта без пути. Для localhost допустим HTTP.');
  }
  if (vk && origin.origin !== vk.origin) throw new Error('SITE_ORIGIN должен совпадать с доменом VK_REDIRECT_URI.');
  const secure = origin?.protocol === 'https:';
  const accounts = openAccounts(accountFile);
  const prefix = secure ? '__Host-' : '';
  const attemptCookie = `${prefix}topiary_vk_attempt`;
  const sessionCookie = `${prefix}topiary_session`;
  const attempts = new Map();
  const sessions = new Map();
  const rates = new Map();

  function pruneExpired() {
    const time = now();
    for (const store of [attempts, sessions, rates]) {
      for (const [key, item] of store) {
        if (item.expiresAt <= time) store.delete(key);
      }
    }
  }

  function json(response, status, value) {
    return response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }).end(JSON.stringify(value));
  }

  function issueSession(request, response, identity) {
    pruneExpired();
    sessions.delete(readCookie(request, sessionCookie));
    if (sessions.size >= STORE_LIMIT) return false;
    const id = randomId();
    sessions.set(id, { ...identity, expiresAt: now() + SESSION_SECONDS * 1000 });
    writeCookie(response, sessionCookie, id, SESSION_SECONDS, secure);
    return true;
  }

  function sameOrigin(request) {
    const fetchSite = request.headers['sec-fetch-site'];
    if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) return false;
    let expected = origin?.origin;
    if (!expected) {
      // An unconfigured installation accepts only loopback hosts, never an arbitrary Host header.
      try {
        const local = new URL(`http://${request.headers.host}`);
        if (!['localhost', '127.0.0.1', '[::1]'].includes(local.hostname) || local.host !== request.headers.host) return false;
        expected = local.origin;
      } catch { return false; }
    }
    return request.headers.origin === expected && request.headers.host?.toLowerCase() === new URL(expected).host;
  }

  function consumeRate(key, limit) {
    pruneExpired();
    let rate = rates.get(key);
    if (!rate) {
      if (rates.size >= STORE_LIMIT * 2) return false;
      rate = { count: 0, expiresAt: now() + RATE_SECONDS * 1000 };
      rates.set(key, rate);
    }
    return ++rate.count <= limit;
  }

  async function readJson(request) {
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')) {
      throw Object.assign(new Error('Нужен JSON-запрос.'), { status: 415 });
    }
    if (Number(request.headers['content-length'] ?? 0) > 4096) {
      throw Object.assign(new Error('Слишком большой запрос.'), { status: 413 });
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > 4096) throw Object.assign(new Error('Слишком большой запрос.'), { status: 413 });
      chunks.push(chunk);
    }
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw Object.assign(new Error('Не удалось прочитать запрос.'), { status: 400 }); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      throw Object.assign(new Error('Некорректные данные формы.'), { status: 400 });
    }
    return body;
  }

  async function passwordAction(request, response, path) {
    if (!sameOrigin(request)) return json(response, 403, { error: 'Обновите страницу и попробуйте снова.' });
    const body = await readJson(request);
    if (path === '/api/auth/logout') {
      sessions.delete(readCookie(request, sessionCookie));
      writeCookie(response, sessionCookie, '', 0, secure);
      return json(response, 200, { authenticated: false });
    }
    // The reverse proxy's forwarded headers are deliberately not trusted.
    const address = request.socket?.remoteAddress ?? 'local';
    if (!consumeRate(`ip:${address}`, 30)) {
      response.setHeader('Retry-After', String(RATE_SECONDS));
      return json(response, 429, { error: 'Слишком много попыток. Попробуйте через 15 минут.' });
    }
    const email = normalizeEmail(body.email);
    if (!email || !validPassword(body.password)) {
      return json(response, 400, { error: 'Укажите корректную почту и пароль от 15 до 128 символов.' });
    }
    if (!consumeRate(`email:${email}`, 10)) {
      response.setHeader('Retry-After', String(RATE_SECONDS));
      return json(response, 429, { error: 'Слишком много попыток. Попробуйте через 15 минут.' });
    }
    const registering = path === '/api/auth/register';
    if (registering && body.password !== body.confirmPassword) {
      return json(response, 400, { error: 'Пароли не совпадают.' });
    }
    const account = await (registering ? accounts.register(email, body.password) : accounts.authenticate(email, body.password));
    if (!account) return json(response, registering ? 409 : 401, {
      error: registering ? 'Не удалось зарегистрировать эту почту. Попробуйте войти.' : 'Неверная почта или пароль.',
    });
    if (!issueSession(request, response, { account, provider: 'email' })) {
      return json(response, 503, { error: 'Сервер занят. Попробуйте чуть позже.' });
    }
    return json(response, registering ? 201 : 200, { authenticated: true, account: { email: account.email } });
  }

  function startVk(request, response) {
    if (!vk) return redirect(response, '/?login=unconfigured#login');

    pruneExpired();
    attempts.delete(readCookie(request, attemptCookie));
    if (attempts.size >= STORE_LIMIT) return redirect(response, '/?login=error#login');

    const attemptId = randomId();
    const state = randomId();
    const verifier = randomId();
    attempts.set(attemptId, { state, verifier, expiresAt: now() + ATTEMPT_SECONDS * 1000 });
    writeCookie(response, attemptCookie, attemptId, ATTEMPT_SECONDS, vk.secure);

    const authorize = new URL('/authorize', VK_ORIGIN);
    authorize.search = new URLSearchParams({
      response_type: 'code',
      client_id: vk.clientId,
      redirect_uri: vk.redirectUri,
      state,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 's256',
    });
    redirect(response, authorize.href);
  }

  async function finishVk(request, response, params) {
    const failed = '/?login=error#login';
    if (!vk) return redirect(response, '/?login=unconfigured#login');

    pruneExpired();
    const attemptId = readCookie(request, attemptCookie);
    const attempt = attempts.get(attemptId);
    if (!attempt || singleParam(params, 'state') !== attempt.state) return redirect(response, failed);
    attempts.delete(attemptId);

    if (params.has('error')) {
      const cancelled = singleParam(params, 'error') === 'access_denied' && !params.has('code');
      return redirect(response, cancelled ? '/?login=cancelled#login' : failed);
    }

    const code = singleParam(params, 'code');
    const deviceId = singleParam(params, 'device_id');
    if (!code || code.length > 4096 || !deviceId || deviceId.length > 512) return redirect(response, failed);

    try {
      const exchangeUrl = new URL('/oauth2/auth', VK_ORIGIN);
      exchangeUrl.search = new URLSearchParams({
        grant_type: 'authorization_code',
        redirect_uri: vk.redirectUri,
        client_id: vk.clientId,
        code_verifier: attempt.verifier,
        state: attempt.state,
        device_id: deviceId,
      });
      const exchange = await fetchVk(exchangeUrl, {
        method: 'POST',
        body: new URLSearchParams({ code }),
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
      });
      if (!exchange.ok) return redirect(response, failed);

      const token = await exchange.json();
      if (!token || token.error || token.state !== attempt.state ||
          typeof token.access_token !== 'string' || !token.access_token.trim() ||
          !Number.isSafeInteger(token.user_id) || token.user_id <= 0) {
        return redirect(response, failed);
      }

      if (!issueSession(request, response, { userId: token.user_id, provider: 'vk' })) return redirect(response, failed);
      return redirect(response, '/#login');
    } catch {
      return redirect(response, failed);
    }
  }

  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');

    try {
      const url = new URL(request.url, 'http://site.invalid');
      if (url.origin !== 'http://site.invalid') return response.writeHead(400).end();

      if (origin && request.headers.host?.toLowerCase() !== origin.host) {
        if (request.method !== 'GET') return json(response, 403, { error: 'Откройте основной адрес сайта.' });
        const canonical = new URL(origin.origin);
        canonical.pathname = url.pathname;
        canonical.search = url.search;
        return redirect(response, canonical.href);
      }

      if (POST_PATHS.has(url.pathname)) {
        if (request.method !== 'POST') return response.writeHead(405, { Allow: 'POST' }).end();
        return await passwordAction(request, response, url.pathname);
      }
      if (request.method !== 'GET') return response.writeHead(405, { Allow: 'GET' }).end();

      if (CALLBACK_PATHS.has(url.pathname)) {
        if (vk && url.pathname !== vk.callbackPath) return response.writeHead(404).end();
        return await finishVk(request, response, url.searchParams);
      }

      switch (url.pathname) {
        case '/api/auth/session': {
          const session = sessions.get(readCookie(request, sessionCookie));
          const authenticated = Boolean(session && session.expiresAt > now());
          response.writeHead(200, { 'Content-Type': 'application/json' });
          return response.end(JSON.stringify({
            authenticated, providers: vk ? ['email', 'vk'] : ['email'],
            ...(authenticated && session.account ? { account: { email: session.account.email } } : {}),
          }));
        }
        case '/api/auth/vk/start':
          return startVk(request, response);
        default: {
          const asset = assets.get(url.pathname);
          if (!asset) return response.writeHead(404).end();
          const [filename, type] = asset;
          const body = readFileSync(new URL(filename, import.meta.url));
          return response.writeHead(200, { 'Content-Type': `${type}; charset=utf-8` }).end(body);
        }
      }
    } catch (error) {
      const status = [400, 413, 415, 503].includes(error.status) ? error.status : 500;
      return json(response, status, { error: status === 500 ? 'Не удалось выполнить запрос. Попробуйте позже.' : error.message });
    }
  });

  const cleanup = setInterval(pruneExpired, 60000).unref();
  server.once('close', () => { clearInterval(cleanup); accounts.close(); });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8080);
  const site = createSiteServer({
    clientId: process.env.VK_CLIENT_ID,
    redirectUri: process.env.VK_REDIRECT_URI,
    siteOrigin: process.env.SITE_ORIGIN,
    accountFile: process.env.AUTH_DB_PATH || defaultAccountFile(),
  });
  site.listen(port, '127.0.0.1', () => {
    console.log(`Топиарий Сад: http://127.0.0.1:${site.address().port}/#login`);
  });
}
