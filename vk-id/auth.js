const loginStatus = document.querySelector('#login-status');
const loginButtons = document.querySelectorAll('[data-login-provider]');

const loginResults = new Map([
  ['cancelled', 'Вход отменён. Можно попробовать снова.'],
  ['error', 'Войти не удалось. Попробуйте ещё раз.'],
  ['unconfigured', 'VK ID ещё не настроен.'],
]);

const loginPageUrl = new URL(window.location.href);
const returnMessage = loginResults.get(loginPageUrl.searchParams.get('login'));

if (loginPageUrl.searchParams.has('login') && window.location.protocol !== 'file:') {
  loginPageUrl.searchParams.delete('login');
  window.history.replaceState(null, '', loginPageUrl);
}

for (const button of loginButtons) {
  button.addEventListener('click', () => {
    const provider = button.dataset.loginProvider;
    window.location.assign(`/api/auth/${provider}/start`);
  });
}

async function refreshLogin() {
  for (const button of loginButtons) {
    button.disabled = true;
  }

  loginStatus.textContent = 'Проверяем доступность входа…';

  try {
    const response = await fetch('/api/auth/session', {
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error('Не удалось проверить сессию');

    const session = await response.json();
    if (typeof session.authenticated !== 'boolean' || !Array.isArray(session.providers)) {
      throw new Error('Некорректный ответ сервера');
    }

    if (session.authenticated) {
      loginStatus.textContent = 'Вы вошли в аккаунт.';
      return;
    }

    for (const button of loginButtons) {
      button.disabled = !session.providers.includes(button.dataset.loginProvider);
    }

    const canSignIn = Array.from(loginButtons).some(button => !button.disabled);
    loginStatus.textContent = returnMessage || (canSignIn
      ? 'Выберите способ входа.'
      : 'VK ID ещё не настроен.');
  } catch {
    loginStatus.textContent = returnMessage || 'Вход пока недоступен. Сервер сайта не подключён или не отвечает.';
  }
}

if (window.location.protocol !== 'file:') {
  refreshLogin();
  window.addEventListener('pageshow', event => {
    if (event.persisted) refreshLogin();
  });
}
