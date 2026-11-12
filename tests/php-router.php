<?php
declare(strict_types=1);
// Local test server only. Apache uses .htaccess on the real hosting.
if (PHP_SAPI !== 'cli-server') { http_response_code(404); exit; }
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (str_starts_with($path, '/api/auth/') || $path === '/auth/vkid') {
    require dirname(__DIR__) . '/vk-auth.php';
    exit;
}
$public = ['/', '/index.html', '/script.js', '/style.css', '/auth.css', '/vk-id/auth.js'];
if (!in_array($path, $public, true)) { http_response_code(404); exit; }
return false;
