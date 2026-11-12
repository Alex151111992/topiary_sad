const loginStatus = document.querySelector('#login-status');
const loginButtons = document.querySelectorAll('[data-login-provider]');
const loginForm = document.querySelector('#email-login');
const registerForm = document.querySelector('#email-register');
const chooseLogin = document.querySelector('#choose-login');
const chooseRegister = document.querySelector('#choose-register');
const logoutButton = document.querySelector('#logout-button');
let providers = [];
let busy = false;
let sessionRequest = 0;

const loginResults = new Map([
  ['cancelled', 'Вход через VK отменён. Можно попробовать снова или войти по почте.'],
  ['error', 'Войти через VK не удалось. Попробуйте ещё раз или войдите по почте.'],
  ['unconfigured', 'Вход через VK пока недоступен. Можно войти по почте.'],
]);
const loginPageUrl = new URL(window.location.href);
let returnMessage = loginResults.get(loginPageUrl.searchParams.get('login'));
if (loginPageUrl.searchParams.has('login') && window.location.protocol !== 'file:') {
  loginPageUrl.searchParams.delete('login');
  window.history.replaceState(null, '', loginPageUrl);
}

function status(message, error = false) {
  loginStatus.textContent = message;
  loginStatus.classList.toggle('auth-error', error);
}

function updateButtons() {
  for (const button of loginButtons) button.disabled = busy || !providers.includes(button.dataset.loginProvider);
  for (const form of [loginForm, registerForm]) form.querySelector('[type="submit"]').disabled = busy || !providers.includes('email');
  chooseLogin.disabled = chooseRegister.disabled = logoutButton.disabled = busy;
}

function setBusy(value) {
  busy = value;
  document.querySelector('#login').setAttribute('aria-busy', String(value));
  updateButtons();
}

function showSession(session) {
  const authenticated = session.authenticated;
  document.querySelector('#login-choices').hidden = authenticated;
  document.querySelector('#account-panel').hidden = !authenticated;
  document.querySelector('#login-title').textContent = authenticated ? 'Ваш аккаунт' : 'Вход на сайт';
  document.querySelector('#login-nav').textContent = authenticated ? 'Аккаунт' : 'Войти';
  document.querySelector('#account-label').textContent = authenticated
    ? session.account?.email || 'Вы вошли через VK ID.' : '';
  if (authenticated) {
    loginForm.reset();
    registerForm.reset();
  }
}

function chooseMode(registering) {
  loginForm.hidden = registering;
  registerForm.hidden = !registering;
  chooseLogin.setAttribute('aria-pressed', String(!registering));
  chooseRegister.setAttribute('aria-pressed', String(registering));
  loginForm.querySelector('[name="password"]').value = '';
  registerForm.querySelector('[name="password"]').value = '';
  registerForm.querySelector('[name="confirmPassword"]').value = '';
  status(registering ? 'Создайте аккаунт, чтобы входить по почте.' : 'Введите почту и пароль.');
}
chooseLogin.addEventListener('click', () => chooseMode(false));
chooseRegister.addEventListener('click', () => chooseMode(true));
for (const button of loginButtons) {
  button.addEventListener('click', () => window.location.assign(`/api/auth/${button.dataset.loginProvider}/start`));
}

async function refreshLogin(message) {
  const requestId = ++sessionRequest;
  setBusy(true);
  try {
    const response = await fetch('/api/auth/session', {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error();
    const session = await response.json();
    if (typeof session.authenticated !== 'boolean' || !Array.isArray(session.providers)) throw new Error();
    if (requestId !== sessionRequest) return;
    providers = session.providers;
    showSession(session);
    document.querySelector('#vk-availability').textContent = providers.includes('vk')
      ? '' : 'Вход через VK пока недоступен. Можно использовать почту.';
    status(message || (session.authenticated ? 'Вы вошли в аккаунт.' : returnMessage || 'Выберите удобный способ входа.'));
    returnMessage = undefined;
  } catch {
    if (requestId !== sessionRequest) return;
    providers = [];
    status('Не удалось связаться с сервером. Обновите страницу и попробуйте снова.', true);
  } finally {
    if (requestId === sessionRequest) setBusy(false);
  }
}

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
  });
  let result;
  try { result = await response.json(); } catch { throw new Error('Сервер не ответил. Попробуйте позже.'); }
  if (!response.ok) throw new Error(result.error || 'Не удалось выполнить запрос.');
  return result;
}

for (const form of [loginForm, registerForm]) {
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !providers.includes('email') || !form.reportValidity()) return;
    const body = Object.fromEntries(new FormData(form));
    if (form === registerForm && body.password !== body.confirmPassword) {
      status('Пароли не совпадают. Проверьте повторный ввод.', true);
      return;
    }
    setBusy(true);
    status(form === registerForm ? 'Создаём аккаунт…' : 'Входим…');
    try {
      const result = await post(form.getAttribute('action'), body);
      if (result.authenticated !== true) throw new Error('Не удалось подтвердить вход.');
      await refreshLogin(form === registerForm ? 'Аккаунт создан. Вы вошли на сайт.' : 'Вы вошли в аккаунт.');
    } catch (error) {
      status(error.name === 'TimeoutError' || error instanceof TypeError
        ? 'Не удалось связаться с сервером. Попробуйте снова.' : error.message, true);
    } finally {
      form.querySelector('[name="password"]').value = '';
      if (form === registerForm) form.querySelector('[name="confirmPassword"]').value = '';
      setBusy(false);
    }
  });
}

logoutButton.addEventListener('click', async () => {
  if (busy) return;
  setBusy(true);
  try {
    await post('/api/auth/logout', {});
    await refreshLogin('Вы вышли из аккаунта.');
  } catch { status('Не удалось выйти. Проверьте соединение и попробуйте снова.', true); }
  finally { setBusy(false); }
});

if (window.location.protocol !== 'file:') {
  refreshLogin();
  window.addEventListener('pageshow', event => { if (event.persisted) refreshLogin(); });
}
