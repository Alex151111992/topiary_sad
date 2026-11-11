<?php
declare(strict_types=1);

/* ============ НАСТРОЙКИ — заполните эти две строки ============ */
$VK_CLIENT_ID    = getenv('VK_CLIENT_ID')    ?: '54889426'; // ID вашего приложения VK ID, например '51912345'
$VK_REDIRECT_URI = getenv('VK_REDIRECT_URI') ?: 'https://www.topiary-sad.ru/api/auth/vk/callback'; // 'https://topiary-sad.ru/api/auth/vk/callback'

const VK_ORIGIN       = 'https://id.vk.ru';
const CALLBACK_PATH   = '/api/auth/vk/callback';
const ATTEMPT_SECONDS = 600;   // срок жизни попытки входа
const SESSION_SECONDS = 3600;  // срок жизни сессии
const STORE_LIMIT     = 2048;  // максимум попыток/сессий

function readVkConfig(string $clientId, string $redirectUri): ?array {
    if ($clientId === '' && $redirectUri === '') return null;
    if (!preg_match('/^[1-9]\d*$/', $clientId) || $redirectUri === '') {
        http_response_code(500);
        exit('Укажите VK_CLIENT_ID и VK_REDIRECT_URI.');
    }
    $u = parse_url($redirectUri);
    $loopback = in_array($u['host'] ?? '', ['127.0.0.1', 'localhost'], true);
    $validScheme = ($u['scheme'] ?? '') === 'https'
        || (($u['scheme'] ?? '') === 'http' && $loopback);
    if (!$validScheme || ($u['path'] ?? '') !== CALLBACK_PATH
        || isset($u['user']) || isset($u['pass']) || preg_match('/[?#]/', $redirectUri)) {
        http_response_code(500);
        exit('VK_REDIRECT_URI должен вести на ' . CALLBACK_PATH . ' по HTTPS. HTTP допустим только для локального адреса.');
    }
    return ['clientId' => $clientId, 'redirectUri' => $redirectUri, 'secure' => $u['scheme'] === 'https'];
}

function base64url(string $bytes): string { return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='); }
function randomId(): string { return base64url(random_bytes(32)); }

function readCookie(string $name): ?string {
    $v = $_COOKIE[$name] ?? '';
    return $v !== '' && preg_match('/^[A-Za-z0-9_-]{43}$/', $v) ? $v : null;
}

function writeCookie(string $name, string $id, int $seconds, bool $secure): void {
    setcookie($name, $id, [
        'expires' => time() + $seconds, 'path' => '/',
        'secure' => $secure, 'httponly' => true, 'samesite' => 'Lax',
    ]);
}

function redirect(string $location): never {
    http_response_code(303);
    header('Location: ' . $location);
    exit;
}

function singleParam(string $key): ?string {
    $values = [];
    foreach (explode('&', $_SERVER['QUERY_STRING'] ?? '') as $pair) {
        [$k, $v] = array_pad(explode('=', $pair, 2), 2, null);
        if (urldecode((string)$k) === $key) $values[] = urldecode((string)$v);
    }
    return count($values) === 1 ? $values[0] : null;
}

/* ---- Хранилище попыток и сессий: файлы во временной папке ---- */
function storeDir(): string {
    $dir = rtrim(sys_get_temp_dir(), '/') . '/topiary-vk-store';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}
function storePath(string $kind, ?string $id): string {
    return storeDir() . '/' . $kind . '-' . preg_replace('/[^A-Za-z0-9_-]/', '', (string)$id) . '.json';
}
function storeGet(string $kind, ?string $id): ?array {
    $file = storePath($kind, $id);
    if (!$id || !is_file($file)) return null;
    $data = json_decode((string)file_get_contents($file), true);
    if (!is_array($data)) { @unlink($file); return null; }
    return $data;
}
function storeSet(string $kind, string $id, array $data): void {
    file_put_contents(storePath($kind, $id), json_encode($data), LOCK_EX);
}
function storeCount(string $kind): int {
    return count(glob(storeDir() . '/' . $kind . '-*.json') ?: []);
}
function pruneExpired(int $now): void {
    foreach (glob(storeDir() . '/*.json') ?: [] as $file) {
        $data = json_decode((string)@file_get_contents($file), true);
        if (is_array($data) && ($data['expiresAt'] ?? 0) <= $now) @unlink($file);
    }
}

/* ---- Старт входа: одноразовая попытка + PKCE ---- */
function startVk(?array $vk, bool $secure, string $attemptCookie): void {
    if (!$vk) redirect('/?login=unconfigured#login');
    pruneExpired(time());
    $old = readCookie($attemptCookie);
    if ($old) @unlink(storePath('attempt', $old));
    if (storeCount('attempt') >= STORE_LIMIT) redirect('/?login=error#login');

    $attemptId = randomId();
    $state = randomId();
    $verifier = randomId();
    storeSet('attempt', $attemptId, [
        'state' => $state, 'verifier' => $verifier,
        'expiresAt' => time() + ATTEMPT_SECONDS,
    ]);
    writeCookie($attemptCookie, $attemptId, ATTEMPT_SECONDS, $secure);

    $authorize = VK_ORIGIN . '/authorize?' . http_build_query([
        'response_type' => 'code',
        'client_id' => $vk['clientId'],
        'redirect_uri' => $vk['redirectUri'],
        'state' => $state,
        'code_challenge' => base64url(hash('sha256', $verifier, true)),
        'code_challenge_method' => 's256',
    ]);
    redirect($authorize);
}

/* ---- Обмен кода на токен (cURL вместо fetchVk, таймаут 8 с) ---- */
function exchangeToken(array $vk, string $code, string $deviceId, string $verifier, string $state): array {
    $url = VK_ORIGIN . '/oauth2/auth?' . http_build_query([
        'grant_type' => 'authorization_code',
        'redirect_uri' => $vk['redirectUri'],
        'client_id' => $vk['clientId'],
        'code_verifier' => $verifier,
        'state' => $state,
        'code' => $code,
        'device_id' => $deviceId,
    ]);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_POSTFIELDS => '',
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    ]);
    $body = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($status !== 200 || !is_string($body)) throw new RuntimeException('token exchange failed');
    $token = json_decode($body, true);
    if (!is_array($token)) throw new RuntimeException('bad token payload');
    return $token;
}

/* ---- Завершение входа ---- */
function finishVk(?array $vk, bool $secure, string $attemptCookie, string $sessionCookie): void {
    $failed = '/?login=error#login';
    if (!$vk) redirect('/?login=unconfigured#login');

    pruneExpired(time());
    $attemptId = readCookie($attemptCookie);
    $attempt = storeGet('attempt', $attemptId);
    if (!$attempt || singleParam('state') !== $attempt['state']) redirect($failed);
    @unlink(storePath('attempt', $attemptId));

    if (singleParam('error') !== null) {
        $cancelled = singleParam('error') === 'access_denied' && singleParam('code') === null;
        redirect($cancelled ? '/?login=cancelled#login' : $failed);
    }

    $code = singleParam('code');
    $deviceId = singleParam('device_id');
    if (!$code || strlen($code) > 4096 || !$deviceId || strlen($deviceId) > 512) redirect($failed);

    try {
        $token = exchangeToken($vk, $code, $deviceId, $attempt['verifier'], $attempt['state']);
        if (($token['state'] ?? null) !== $attempt['state']
            || !isset($token['access_token'], $token['user_id'])) {
            redirect($failed);
        }
        $sessionId = randomId();
        storeSet('session', $sessionId, [
            'userId' => $token['user_id'],
            'expiresAt' => time() + SESSION_SECONDS,
        ]);
        writeCookie($sessionCookie, $sessionId, SESSION_SECONDS, $secure);
        redirect('/#login');
    } catch (Throwable) {
        redirect($failed);
    }
}

/* ================= Диспетчер ================= */
$now = time();
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    exit;
}

$vk = readVkConfig($VK_CLIENT_ID, $VK_REDIRECT_URI);
$secure = (bool)($vk['secure'] ?? false);
$prefix = $secure ? '__Host-' : '';
$attemptCookie = $prefix . 'topiary_vk_attempt';
$sessionCookie = $prefix . 'topiary_session';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

switch ($path) {
    case '/api/auth/session':
        pruneExpired($now);
        $session = storeGet('session', readCookie($sessionCookie));
        $authenticated = $session !== null && ($session['expiresAt'] ?? 0) > $now;
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['authenticated' => $authenticated, 'providers' => $vk ? ['vk'] : []], JSON_UNESCAPED_UNICODE);
        exit;

    case '/api/auth/vk/start':
        startVk($vk, $secure, $attemptCookie);

    case CALLBACK_PATH:
        finishVk($vk, $secure, $attemptCookie, $sessionCookie);

    default:
        http_response_code(404);
        exit;
}