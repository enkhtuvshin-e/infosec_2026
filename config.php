<?php
putenv('OPENSSL_CONF=C:/xampp/apache/conf/openssl.cnf');

define('DB_HOST', 'localhost');
define('DB_NAME', 'vault_demo');
define('DB_USER', 'root');
define('DB_PASS', '');

define('ENCRYPTION_KEY',       'VaultDemoKey2024!@#$%^&*()_+1234');
define('ENCRYPTION_IV_LENGTH', 16);

define('OPENSSL_CNF',          'C:/xampp/apache/conf/openssl.cnf');
define('RSA_PRIVATE_KEY_FILE', __DIR__ . '/keys/private.pem');
define('RSA_PUBLIC_KEY_FILE',  __DIR__ . '/keys/public.pem');

session_start();

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        try {
            $pdo = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER, DB_PASS,
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ]
            );
        } catch (PDOException $e) {
            die("DB холболт амжилтгүй: " . $e->getMessage());
        }
    }
    return $pdo;
}
