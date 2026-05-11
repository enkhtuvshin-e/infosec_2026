<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/crypto.php';
?>
<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="UTF-8">
<title>RSA Key Generator</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 40px; }
h2   { color: #f0f6fc; }
p    { margin: 8px 0; font-size: 15px; }
.ok  { color: #3fb950; }
.err { color: #f85149; }
.info{ color: #79c0ff; }
.box { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 24px; max-width: 600px; }
a    { color: #58a6ff; }
</style>
</head>
<body>
<div class="box">
<h2>🔑 RSA Түлхүүр Үүсгэгч</h2>

<?php
try {
    $keyDir = __DIR__ . '/keys';

    if (!is_dir($keyDir)) {
        mkdir($keyDir, 0700, true);
        echo "<p class='info'>📁 keys/ хавтас үүслээ</p>";
    } else {
        echo "<p class='info'>📁 keys/ хавтас байна</p>";
    }

    echo "<p class='info'>⚙️ openssl.cnf: " . OPENSSL_CNF . "</p>";
    echo "<p class='info'>📄 openssl.cnf байна: " . (file_exists(OPENSSL_CNF) ? '✅ Тийм' : '❌ Үгүй') . "</p>";

    VaultCrypto::generateRSAKeys();

    echo "<p class='ok'>✅ RSA-2048 private key үүслээ: keys/private.pem</p>";
    echo "<p class='ok'>✅ RSA-2048 public key үүслээ: keys/public.pem</p>";
    file_put_contents($keyDir . '/.htaccess', "Deny from all\n");
    echo "<p class='ok'>🛡️ keys/.htaccess хамгаалалт нэмлээ</p>";

    echo "<br><p>👉 <a href='index.php'>The Vault руу орох</a></p>";

} catch (Exception $e) {
    echo "<p class='err'>❌ Алдаа: " . htmlspecialchars($e->getMessage()) . "</p>";
}
?>
</div>
</body>
</html>
