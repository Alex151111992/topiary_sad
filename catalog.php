<?php
declare(strict_types=1);

// Included by vk-auth.php; data and images are stored beside the private account DB.
function catalogDb(): PDO {
    static $ready = false;
    $db = emailDb();
    if ($ready) return $db;
    $db->exec('CREATE TABLE IF NOT EXISTS account_roles (
        provider TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
        PRIMARY KEY(provider, subject)
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL,
        price_cents INTEGER NOT NULL, category TEXT NOT NULL, published INTEGER NOT NULL,
        image TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS catalog_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    // A marker prevents products reappearing if an operator empties the table later.
    $db->exec('BEGIN IMMEDIATE');
    try {
        if (!$db->query("SELECT value FROM catalog_meta WHERE key = 'seeded'")->fetchColumn()) {
            $insert = $db->prepare('INSERT INTO products(name,description,price_cents,category,published,image,updated_at) VALUES(?,?,?,?,1,?,?)');
            foreach ([
                ['Топиар «Шар»','Классический шар из самшита, диаметр 60 см.',450000,'Растения'],
                ['Топиар «Спираль»','Спиральная форма из туи, высота 120 см.',720000,'Растения'],
                ['Топиар «Медведь»','Декоративная фигура медведя из искусственной травы, высота 90 см.',1800000,'Фигуры'],
            ] as $row) $insert->execute([...$row, '/assets/catalog-placeholder.svg', time()]);
            $db->exec("INSERT INTO catalog_meta(key,value) VALUES('seeded','1')");
        }
        $db->exec('COMMIT');
        $ready = true;
    } catch (Throwable $error) { $db->exec('ROLLBACK'); throw $error; }
    return $db;
}

function catalogIdentity(?array $session): ?array {
    if (isset($session['account']['id']) && is_string($session['account']['id'])) {
        return ['email', $session['account']['id']];
    }
    if (isset($session['userId']) && preg_match('/^[1-9][0-9]*$/', (string)$session['userId'])) {
        return ['vk', (string)$session['userId']];
    }
    return null;
}

function catalogIsAdmin(?array $session): bool {
    $identity = catalogIdentity($session);
    if ($identity === null) return false;
    $find = catalogDb()->prepare("SELECT 1 FROM account_roles WHERE provider=? AND subject=? AND role='admin'");
    $find->execute($identity);
    return (bool)$find->fetchColumn();
}

function catalogSession(): array {
    $session = sessionGet(readCookie(SESSION_COOKIE));
    if (catalogIdentity($session) === null) emailJson(401, ['error'=>'Войдите в аккаунт.']);
    if (!catalogIsAdmin($session)) emailJson(403, ['error'=>'Доступ разрешён только администратору.']);
    return $session;
}

function catalogCsrf(string $sid): string {
    // The cookie is a server-generated 256-bit secret, never exposed to script.
    return hash_hmac('sha256', 'topiary-catalog-admin-v1', $sid);
}

function catalogMutation(): void {
    $host = parse_url(SITE_ORIGIN, PHP_URL_HOST) . (parse_url(SITE_ORIGIN, PHP_URL_PORT) ? ':' . parse_url(SITE_ORIGIN, PHP_URL_PORT) : '');
    if (($_SERVER['HTTP_ORIGIN'] ?? '') !== SITE_ORIGIN || strtolower($_SERVER['HTTP_HOST'] ?? '') !== $host ||
        !in_array($_SERVER['HTTP_SEC_FETCH_SITE'] ?? 'same-origin',['same-origin','none'],true) ||
        !hash_equals(catalogCsrf(readCookie(SESSION_COOKIE) ?? ''), $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
        emailJson(403, ['error'=>'Обновите страницу и повторите действие.']);
    }
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 5*1024*1024) emailJson(413,['error'=>'Запрос слишком большой. Фото должно быть не более 4 МБ.']);
}

function catalogRow(array $row, bool $admin): array {
    $product = ['id'=>(int)$row['id'],'name'=>$row['name'],'desc'=>$row['description'],
        'price'=>(int)$row['price_cents']/100,'category'=>$row['category'],'img'=>$row['image']];
    if ($admin) $product += ['published'=>(bool)$row['published'],'version'=>(int)$row['version'],'updatedAt'=>(int)$row['updated_at']];
    return $product;
}

function catalogText(string $field, int $min, int $max): string {
    $value = $_POST[$field] ?? null;
    if (!is_string($value)) emailJson(422,['error'=>'Заполните все поля товара.']);
    $value = trim($value);
    $length = preg_match_all('/./us',$value);
    if ($length === false || $length < $min || $length > $max || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/',$value)) {
        emailJson(422,['error'=>'Проверьте длину названия, описания и категории.']);
    }
    return $value;
}

function catalogImageDir(): string {
    $dir = dirname(emailPrivateDir()) . '/catalog-images';
    if (!is_dir($dir) && !mkdir($dir,0700,true) && !is_dir($dir)) throw new RuntimeException('Cannot create image directory');
    return $dir;
}

function catalogUpload(): ?string {
    $file = $_FILES['photo'] ?? null;
    if ($file === null || ($file['error'] ?? null) === UPLOAD_ERR_NO_FILE) return null;
    if (!is_array($file) || !is_int($file['error'] ?? null) || $file['error'] !== UPLOAD_ERR_OK ||
        !is_string($file['tmp_name'] ?? null) || !is_uploaded_file($file['tmp_name']) ||
        filesize($file['tmp_name']) > 4*1024*1024) {
        emailJson(422,['error'=>'Не удалось загрузить фото. Допустимый размер — до 4 МБ.']);
    }
    if (!extension_loaded('gd') || !extension_loaded('fileinfo')) emailJson(503,['error'=>'На сервере нужно подключить обработку фотографий.']);
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    $extension = ['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp'][$mime] ?? null;
    $size = @getimagesize($file['tmp_name']);
    if (!$extension || !$size || ($size['mime'] ?? '') !== $mime || $size[0] < 1 || $size[1] < 1 ||
        $size[0] > 4096 || $size[1] > 4096 || $size[0]*$size[1] > 8000000) {
        emailJson(422,['error'=>'Выберите настоящее фото JPEG, PNG или WebP, до 4096×4096 и 8 мегапикселей.']);
    }
    $image = @imagecreatefromstring((string)file_get_contents($file['tmp_name']));
    if (!$image) emailJson(422,['error'=>'Фотография повреждена. Выберите другой файл.']);
    $name = bin2hex(random_bytes(16)) . '.' . $extension;
    $path = catalogImageDir() . '/' . $name;
    // Re-encode: do not retain user-controlled filenames, executable payloads or metadata.
    imagealphablending($image,false); imagesavealpha($image,true);
    $ok = match($extension) {
        'jpg'=>imagejpeg($image,$path,88), 'png'=>imagepng($image,$path,6), 'webp'=>imagewebp($image,$path,88)
    };
    if (!$ok) throw new RuntimeException('Cannot write photo');
    @chmod($path,0600);
    return '/media/' . $name;
}

function catalogRemoveUnusedImage(string $image): void {
    if (!preg_match('~^/media/([a-f0-9]{32}\.(?:jpg|png|webp))$~',$image,$match)) return;
    $query = catalogDb()->prepare('SELECT COUNT(*) FROM products WHERE image=?');
    $query->execute([$image]);
    if ((int)$query->fetchColumn() === 0) @unlink(catalogImageDir().'/'.$match[1]);
}

function catalogHandle(string $path): never {
    $method = $_SERVER['REQUEST_METHOD'] ?? '';
    if ($path === '/api/catalog' && $method === 'GET') {
        $rows = catalogDb()->query('SELECT * FROM products WHERE published=1 ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        emailJson(200,['products'=>array_map(fn($row)=>catalogRow($row,false),$rows)]);
    }
    if (preg_match('~^/media/([a-f0-9]{32}\.(jpg|png|webp))$~',$path,$match) && $method === 'GET') {
        $query = catalogDb()->prepare('SELECT MAX(published) FROM products WHERE image=?'); $query->execute([$path]);
        $published = $query->fetchColumn();
        if ($published === null || $published === false || (!(bool)$published && !catalogIsAdmin(sessionGet(readCookie(SESSION_COOKIE))))) {
            http_response_code(404); exit;
        }
        $file = catalogImageDir().'/'.$match[1];
        if (!is_file($file)) { http_response_code(404); exit; }
        header('Content-Type: '.['jpg'=>'image/jpeg','png'=>'image/png','webp'=>'image/webp'][$match[2]]);
        header("Content-Security-Policy: default-src 'none'; sandbox");
        header('Cache-Control: no-store');
        header('Content-Length: '.filesize($file)); readfile($file); exit;
    }
    if (!in_array($path,['/api/admin/session','/api/admin/products'],true)) { http_response_code(404); exit; }
    catalogSession(); // Also checked for read-only admin endpoints, no URL-based privileges.
    if ($path === '/api/admin/session' && $method === 'GET') {
        emailJson(200,['admin'=>true,'csrfToken'=>catalogCsrf(readCookie(SESSION_COOKIE))]);
    }
    if ($path === '/api/admin/products' && $method === 'GET') {
        $rows = catalogDb()->query('SELECT * FROM products ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        emailJson(200,['products'=>array_map(fn($row)=>catalogRow($row,true),$rows)]);
    }
    if ($path !== '/api/admin/products' || $method !== 'POST') { header('Allow: GET, POST'); emailJson(405,['error'=>'Метод не поддерживается.']); }
    catalogMutation();
    if (!str_starts_with($_SERVER['CONTENT_TYPE'] ?? '', 'multipart/form-data;')) emailJson(415,['error'=>'Нужна форма товара.']);
    $name = catalogText('name',1,120); $description = catalogText('desc',0,2000); $category = catalogText('category',1,60);
    $price = $_POST['price'] ?? '';
    if (!is_string($price) || !preg_match('/^(?:0|[1-9][0-9]{0,6})(?:\.[0-9]{1,2})?$/',$price)) emailJson(422,['error'=>'Укажите цену от 0,01 до 9 999 999,99 ₽.']);
    $cents = (int)round((float)$price*100);
    if ($cents < 1) emailJson(422,['error'=>'Цена должна быть больше нуля.']);
    if (!in_array($_POST['published'] ?? null,['0','1'],true)) emailJson(422,['error'=>'Выберите статус публикации.']);
    $id = $_POST['id'] ?? ''; $version = $_POST['version'] ?? '';
    if (!is_string($id) || ($id !== '' && !preg_match('/^[1-9][0-9]{0,15}$/',$id))) emailJson(422,['error'=>'Некорректный номер товара.']);
    $db = catalogDb(); $old = null;
    if ($id !== '') {
        $find = $db->prepare('SELECT * FROM products WHERE id=?'); $find->execute([$id]); $old = $find->fetch(PDO::FETCH_ASSOC);
        if (!$old) emailJson(404,['error'=>'Товар не найден.']);
        if (!is_string($version) || (string)$old['version'] !== $version) emailJson(409,['error'=>'Товар уже изменён. Откройте его заново и повторите правку.']);
    }
    $photo = catalogUpload();
    $image = $photo ?? (($_POST['removePhoto'] ?? '') === '1' ? '/assets/catalog-placeholder.svg' : ($old['image'] ?? '/assets/catalog-placeholder.svg'));
    try {
        $db->beginTransaction();
        $values = [$name,$description,$cents,$category,(int)$_POST['published'],$image,time()];
        if ($old) {
            $save = $db->prepare('UPDATE products SET name=?,description=?,price_cents=?,category=?,published=?,image=?,updated_at=?,version=version+1 WHERE id=? AND version=?');
            $save->execute([...$values,$id,$version]);
            if ($save->rowCount() !== 1) { $db->rollBack(); if ($photo) catalogRemoveUnusedImage($photo); emailJson(409,['error'=>'Товар уже изменён. Откройте его заново.']); }
        } else {
            $save = $db->prepare('INSERT INTO products(name,description,price_cents,category,published,image,updated_at) VALUES(?,?,?,?,?,?,?)');
            $save->execute($values); $id = $db->lastInsertId();
        }
        $db->commit();
    } catch (Throwable $error) {
        if ($db->inTransaction()) $db->rollBack();
        if ($photo) catalogRemoveUnusedImage($photo);
        throw $error;
    }
    if ($old && $old['image'] !== $image) catalogRemoveUnusedImage($old['image']);
    $find = $db->prepare('SELECT * FROM products WHERE id=?'); $find->execute([$id]);
    emailJson($old ? 200 : 201,['product'=>catalogRow($find->fetch(PDO::FETCH_ASSOC),true)]);
}
