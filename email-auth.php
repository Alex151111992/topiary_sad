<?php
declare(strict_types=1);

// Loaded by vk-auth.php. Accounts and sessions share the site's existing cookie.
function emailJson(int $status, array $data): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function emailPrivateDir(): string {
    $file = getenv('AUTH_DB_PATH');
    if (!$file) {
        $home = getenv('HOME');
        if (!$home) throw new RuntimeException('Private data path is not configured');
        $file = $home . '/.local/share/topiary-sad-php/accounts.sqlite';
    }
    if (!preg_match('~^(?:[A-Za-z]:[\\\\/]|/)~', $file)) throw new RuntimeException('Absolute data path required');
    $parent = dirname($file);
    if (!is_dir($parent) && !mkdir($parent, 0700, true) && !is_dir($parent)) throw new RuntimeException('Cannot create data directory');
    $realParent = realpath($parent);
    if ($realParent === false) throw new RuntimeException('Invalid data directory');
    foreach ([__DIR__, $_SERVER['DOCUMENT_ROOT'] ?? __DIR__] as $public) {
        $public = realpath($public);
        if ($public === false) continue;
        $prefix = rtrim(str_replace('\\', '/', $public), '/') . '/';
        $candidate = rtrim(str_replace('\\', '/', $realParent), '/') . '/';
        if (str_starts_with(strtolower($candidate), strtolower($prefix))) throw new RuntimeException('Data must be outside website sources');
    }
    return $realParent . DIRECTORY_SEPARATOR . basename($file);
}

function emailDb(): PDO {
    static $db = null;
    if ($db instanceof PDO) return $db;
    $file = emailPrivateDir();
    $db = new PDO('sqlite:' . $file, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    @chmod($file, 0600);
    $db->exec('PRAGMA busy_timeout = 5000');
    $db->exec('CREATE TABLE IF NOT EXISTS email_accounts (
        id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, salt TEXT NOT NULL,
        password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS email_rates (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL)');
    return $db;
}

function emailAvailable(): bool {
    try { emailDb(); return true; } catch (Throwable $error) { return false; }
}

function emailTakeRate(string $key, int $limit): bool {
    $db = emailDb();
    $key = hash('sha256', $key);
    $db->exec('BEGIN IMMEDIATE');
    try {
        $prune = $db->prepare('DELETE FROM email_rates WHERE expires_at <= ?');
        $prune->execute([time()]);
        $find = $db->prepare('SELECT count FROM email_rates WHERE key = ?');
        $find->execute([$key]);
        $row = $find->fetch(PDO::FETCH_ASSOC);
        if (!$row && (int)$db->query('SELECT COUNT(*) FROM email_rates')->fetchColumn() >= 4096) {
            $db->exec('COMMIT');
            return false;
        }
        $update = $db->prepare('INSERT INTO email_rates(key, count, expires_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count = count + 1');
        $update->execute([$key, time() + 900]);
        $db->exec('COMMIT');
        return ((int)($row['count'] ?? 0) + 1) <= $limit;
    } catch (Throwable $error) {
        $db->exec('ROLLBACK');
        throw $error;
    }
}

function emailPasswordValid(mixed $password): bool {
    if (!is_string($password) || strlen($password) > 512) return false;
    $length = preg_match_all('/./us', $password);
    return $length !== false && $length >= 15 && $length <= 128;
}

function emailHandle(string $path): never {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        emailJson(405, ['error' => 'Используйте POST.']);
    }
    $fetchSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? 'same-origin';
    if (($_SERVER['HTTP_ORIGIN'] ?? '') !== SITE_ORIGIN ||
        strtolower($_SERVER['HTTP_HOST'] ?? '') !== parse_url(SITE_ORIGIN, PHP_URL_HOST) . (parse_url(SITE_ORIGIN, PHP_URL_PORT) ? ':' . parse_url(SITE_ORIGIN, PHP_URL_PORT) : '') ||
        !in_array($fetchSite, ['same-origin', 'none'], true)) {
        emailJson(403, ['error' => 'Обновите страницу и попробуйте снова.']);
    }
    if (!preg_match('~^application/json(?:\s*;\s*charset=utf-8)?$~i', $_SERVER['CONTENT_TYPE'] ?? '')) emailJson(415, ['error' => 'Нужен JSON-запрос.']);
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096) emailJson(413, ['error' => 'Слишком большой запрос.']);
    $raw = file_get_contents('php://input', false, null, 0, 4097);
    if ($raw === false || strlen($raw) > 4096) emailJson(413, ['error' => 'Слишком большой запрос.']);
    $body = json_decode($raw);
    if (!$body instanceof stdClass) emailJson(400, ['error' => 'Некорректные данные формы.']);
    if ($path === '/api/auth/logout') {
        sessionDelete(readCookie(SESSION_COOKIE));
        writeCookie(SESSION_COOKIE, '', 0);
        emailJson(200, ['authenticated' => false]);
    }
    if (!emailTakeRate('ip:' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 30)) {
        header('Retry-After: 900');
        emailJson(429, ['error' => 'Слишком много попыток. Попробуйте через 15 минут.']);
    }
    $email = isset($body->email) && is_string($body->email) ? strtolower(trim($body->email)) : '';
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL) || !emailPasswordValid($body->password ?? null)) {
        emailJson(400, ['error' => 'Укажите корректную почту и пароль от 15 до 128 символов.']);
    }
    if (!emailTakeRate('email:' . $email, 10)) {
        header('Retry-After: 900');
        emailJson(429, ['error' => 'Слишком много попыток. Попробуйте через 15 минут.']);
    }
    $register = $path === '/api/auth/register';
    if ($register && $body->password !== ($body->confirmPassword ?? null)) emailJson(400, ['error' => 'Пароли не совпадают.']);
    $db = emailDb();
    if ($register) {
        $id = bin2hex(random_bytes(16));
        $salt = bin2hex(random_bytes(16));
        $hash = hash_pbkdf2('sha256', $body->password, $salt, 600000, 64);
        $insert = $db->prepare('INSERT INTO email_accounts(id, email, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(email) DO NOTHING');
        $insert->execute([$id, $email, $salt, $hash, time()]);
        if ($insert->rowCount() !== 1) emailJson(409, ['error' => 'Не удалось зарегистрировать эту почту. Попробуйте войти.']);
    } else {
        $find = $db->prepare('SELECT id, email, salt, password_hash FROM email_accounts WHERE email = ?');
        $find->execute([$email]);
        $account = $find->fetch(PDO::FETCH_ASSOC);
        $hash = hash_pbkdf2('sha256', $body->password, $account['salt'] ?? str_repeat('0', 32), 600000, 64);
        $matches = hash_equals($account['password_hash'] ?? str_repeat('0', 64), $hash);
        if (!$account || !$matches) emailJson(401, ['error' => 'Неверная почта или пароль.']);
        $id = $account['id'];
    }
    sessionDelete(readCookie(SESSION_COOKIE));
    $sessionId = randomId();
    sessionSet($sessionId, ['account' => ['id' => $id, 'email' => $email], 'provider' => 'email', 'expiresAt' => nowMs() + SESSION_SECONDS * 1000]);
    writeCookie(SESSION_COOKIE, $sessionId, SESSION_SECONDS);
    emailJson($register ? 201 : 200, ['authenticated' => true, 'account' => ['email' => $email]]);
}
