<?php
declare(strict_types=1);
// Local test server only. Apache uses .htaccess on the real hosting.
if (PHP_SAPI !== 'cli-server') { http_response_code(404); exit; }
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (str_starts_with($path, '/api/') || str_starts_with($path, '/media/') || $path === '/auth/vkid') {
    require dirname(__DIR__) . '/vk-auth.php';
    exit;
}
if ($path === '/admin' || $path === '/admin/') { require dirname(__DIR__).'/admin.html'; exit; }
if ($path === '/tests/mobile-preview.html') { require __DIR__.'/mobile-preview.html'; exit; }
$public = ['/', '/index.html', '/script.js', '/style.css', '/auth.css', '/vk-id/auth.js', '/admin.html', '/admin.js', '/admin.css', '/assets/catalog-placeholder.svg'];
if (!in_array($path, $public, true)) { http_response_code(404); exit; }
return false;
