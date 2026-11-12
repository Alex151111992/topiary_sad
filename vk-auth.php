<?php
declare(strict_types=1);

const VK_CLIENT_ID    = '54889426';
define('VK_REDIRECT_URI', getenv('VK_REDIRECT_URI') ?: 'https://www.topiary-sad.ru/api/auth/vk/callback');
define('SITE_ORIGIN', getenv('SITE_ORIGIN') ?: 'https://www.topiary-sad.ru');
const VK_ORIGIN       = 'https://id.vk.ru';
const ATTEMPT_SECONDS = 600;
const SESSION_SECONDS = 3600;
define('SECURE', str_starts_with(SITE_ORIGIN, 'https://'));
define('ATTEMPT_COOKIE', (SECURE ? '__Host-' : '') . 'topiary_vk_attempt');
define('SESSION_COOKIE', (SECURE ? '__Host-' : '') . 'topiary_session');
require_once __DIR__ . '/email-auth.php';
$site = parse_url(SITE_ORIGIN);
if (!$site || isset($site['user']) || isset($site['pass']) ||
    isset($site['query']) || isset($site['fragment']) || isset($site['path']) ||
    (!SECURE && !(($site['scheme'] ?? '') === 'http' && in_array($site['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]'], true)))) {
    emailJson(503, ['error' => 'Нужно настроить адрес сайта.']);
}

function nowMs(): int { return (int)(microtime(true) * 1000); }

function randomId(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function storeDir(): string {
    $dir = dirname(emailPrivateDir()) . '/sessions';
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) throw new RuntimeException('Session directory unavailable');
    return $dir;
}

function redirect(string $location): never {
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    header('Location: ' . $location, true, 303);
    exit;
}

function writeCookie(string $name, string $value, int $seconds): void {
    header('Set-Cookie: ' . $name . '=' . $value . '; Path=/; Max-Age=' . $seconds
        . '; HttpOnly; SameSite=Lax' . (SECURE ? '; Secure' : ''), false);
}

function readCookie(string $name): ?string {
    $raw = $_COOKIE[$name] ?? '';
    return is_string($raw) && preg_match('/^[A-Za-z0-9_-]{43}$/', $raw) ? $raw : null;
}

function singleParam(string $key): ?string {
    return isset($_GET[$key]) && is_string($_GET[$key]) && $_GET[$key] !== '' ? $_GET[$key] : null;
}

function attemptSet(string $id, array $data): void {
    file_put_contents(storeDir() . '/a_' . hash('sha256', $id) . '.json', json_encode($data), LOCK_EX);
}
function attemptGet(?string $id): ?array {
    if (!$id) return null;
    $path = storeDir() . '/a_' . hash('sha256', $id) . '.json';
    if (!is_file($path)) return null;
    $data = json_decode((string)file_get_contents($path), true);
    if (!is_array($data) || ($data['expiresAt'] ?? 0) <= nowMs()) { @unlink($path); return null; }
    return $data;
}
function attemptDelete(?string $id): void {
    if ($id) @unlink(storeDir() . '/a_' . hash('sha256', $id) . '.json');
}

function sessionSet(string $id, array $data): void {
    $path = storeDir() . '/s_' . hash('sha256', $id) . '.json';
    if (file_put_contents($path, json_encode($data), LOCK_EX) === false) throw new RuntimeException('Session storage unavailable');
    @chmod($path, 0600);
}
function sessionGet(?string $id): ?array {
    if (!$id) return null;
    $path = storeDir() . '/s_' . hash('sha256', $id) . '.json';
    if (!is_file($path)) return null;
    $data = json_decode((string)file_get_contents($path), true);
    if (!is_array($data) || ($data['expiresAt'] ?? 0) <= nowMs()) { @unlink($path); return null; }
    return $data;
}
function sessionDelete(?string $id): void {
    if ($id) @unlink(storeDir() . '/s_' . hash('sha256', $id) . '.json');
}

function startVk(): never {
    $attemptId = randomId();
    $state = randomId();
    $verifier = randomId();
    attemptSet($attemptId, ['state' => $state, 'verifier' => $verifier, 'expiresAt' => nowMs() + ATTEMPT_SECONDS * 1000]);
    writeCookie(ATTEMPT_COOKIE, $attemptId, ATTEMPT_SECONDS);

    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $query = http_build_query([
        'response_type' => 'code',
        'client_id' => VK_CLIENT_ID,
        'redirect_uri' => VK_REDIRECT_URI,
        'state' => $state,
        'code_challenge' => $challenge,
        'code_challenge_method' => 's256',
    ]);
    redirect(VK_ORIGIN . '/authorize?' . $query);
}

function finishVk(): never {
    $failed = '/?login=error#login';

    $attemptId = readCookie(ATTEMPT_COOKIE);
    $attempt = attemptGet($attemptId);
    if (!$attempt || singleParam('state') !== $attempt['state']) redirect($failed);
    attemptDelete($attemptId);

    if (isset($_GET['error'])) {
        $cancelled = ($_GET['error'] === 'access_denied' && !isset($_GET['code']));
        redirect($cancelled ? '/?login=cancelled#login' : $failed);
    }

    $code = singleParam('code');
    $deviceId = singleParam('device_id');
    if (!$code || strlen($code) > 4096 || !$deviceId || strlen($deviceId) > 512) redirect($failed);

    // Обмен: все параметры в query-строке, в теле — только code (как в server.mjs)
    $query = http_build_query([
        'grant_type' => 'authorization_code',
        'redirect_uri' => VK_REDIRECT_URI,
        'client_id' => VK_CLIENT_ID,
        'code_verifier' => $attempt['verifier'],
        'state' => $attempt['state'],
        'device_id' => $deviceId,
    ]);
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => http_build_query(['code' => $code]),
        'timeout' => 8,
        'ignore_errors' => true,
    ]]);
    $body = @file_get_contents(VK_ORIGIN . '/oauth2/auth?' . $query, false, $context);
    if ($body === false) redirect($failed);

    $token = json_decode($body, true);
    $userId = $token['user_id'] ?? null;
    $userIdOk = is_int($userId) ? ($userId > 0) : (is_string($userId) && ctype_digit($userId) && (int)$userId > 0);
    if (!is_array($token)
        || isset($token['error'])
        || ($token['state'] ?? null) !== $attempt['state']
        || !is_string($token['access_token'] ?? null) || !trim($token['access_token'])
        || !$userIdOk) {
        redirect($failed);
    }

    sessionDelete(readCookie(SESSION_COOKIE));
    $sid = randomId();
    sessionSet($sid, ['userId' => (int)$userId, 'expiresAt' => nowMs() + SESSION_SECONDS * 1000]);
    writeCookie(SESSION_COOKIE, $sid, SESSION_SECONDS);
    redirect('/#login');
}

// --- Маршрутизация ---
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
try {
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    $host = ($site['host'] ?? '') . (isset($site['port']) ? ':' . $site['port'] : '');
    if (strtolower($_SERVER['HTTP_HOST'] ?? '') !== $host) {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') emailJson(403, ['error' => 'Откройте основной адрес сайта.']);
        redirect(SITE_ORIGIN . '/#login');
    }
    if (in_array($path, ['/api/auth/register', '/api/auth/login', '/api/auth/logout'], true)) emailHandle($path);
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

switch ($path) {
    case '/api/auth/session':
        $session = sessionGet(readCookie(SESSION_COOKIE));
        $result = ['authenticated' => $session !== null, 'providers' => emailAvailable() ? ['email', 'vk'] : ['vk']];
        if ($session && isset($session['account']['email'])) $result['account'] = ['email' => $session['account']['email']];
        emailJson(200, $result);

    case '/api/auth/vk/start':
        startVk();

    case '/api/auth/vk/callback':
    case '/auth/vkid':
        if ($path !== parse_url(VK_REDIRECT_URI, PHP_URL_PATH)) { http_response_code(404); exit; }
        finishVk();

    default:
        http_response_code(404);
        exit;
}
} catch (Throwable $error) {
    emailJson(503, ['error' => 'Вход временно недоступен. Попробуйте позже.']);
}
