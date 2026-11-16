<?php
declare(strict_types=1);
// An operator runs this on the hosting. It is not an HTTP route.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__).'/email-auth.php';
require dirname(__DIR__).'/catalog.php';
if (count($argv)!==4 || !in_array($argv[1],['grant','revoke'],true) || !in_array($argv[2],['email','vk'],true)) {
    fwrite(STDERR,"Usage: php bin/set-admin.php grant|revoke email|vk account\n"); exit(1);
}
try {
    $db=catalogDb(); $subject=$argv[3];
    if ($argv[2]==='email') {
        $find=$db->prepare('SELECT id FROM email_accounts WHERE email=?'); $find->execute([strtolower(trim($subject))]);
        $subject=$find->fetchColumn();
        if (!$subject) throw new RuntimeException('Create the account first, then assign its role.');
    } elseif (!preg_match('/^[1-9][0-9]*$/',$subject)) throw new RuntimeException('Use the numeric VK user ID.');
    if ($argv[1]==='grant') {
        $query=$db->prepare("INSERT INTO account_roles(provider,subject,role) VALUES(?,?,'admin') ON CONFLICT(provider,subject) DO UPDATE SET role='admin'");
    } else $query=$db->prepare('DELETE FROM account_roles WHERE provider=? AND subject=?');
    $query->execute([$argv[2],$subject]);
    echo "Role updated.\n";
} catch (Throwable $error) { fwrite(STDERR,$error->getMessage()."\n"); exit(1); }
