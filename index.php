<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/crypto.php';

$message = '';
$result  = null;
$tab     = $_GET['tab'] ?? 'encrypt';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = VaultCrypto::generateToken();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf']) || $_POST['csrf'] !== $_SESSION['csrf_token']) {
        die('CSRF токен буруу!');
    }

    $action = $_POST['action'] ?? '';

    try {
      
        if ($action === 'encrypt') {
            $label = htmlspecialchars(trim($_POST['label'] ?? ''));
            $text  = $_POST['plaintext'] ?? '';

            if ($label && $text) {
                $enc  = VaultCrypto::aesEncrypt($text);
                $sig  = VaultCrypto::rsaSign($text);
                $sha  = VaultCrypto::sha256($text);
                $md5h = VaultCrypto::md5Hash($text);

                $db = getDB();
                $st = $db->prepare("INSERT INTO vault_data (label, encrypted_text, iv, hash_sha256, hash_md5, signature) VALUES (?,?,?,?,?,?)");
                $st->execute([$label, $enc['cipher'], $enc['iv'], $sha, $md5h, $sig]);

                $message = "success:✅ '{$label}' амжилттай шифрлэж хадгаллаа!";
                $result  = [
                    'cipher'    => $enc['cipher'],
                    'iv'        => $enc['iv'],
                    'sha256'    => $sha,
                    'md5'       => $md5h,
                    'signature' => $sig,
                ];
            } else {
                $message = "error:❌ Нэр болон текст оруулна уу!";
            }
        }

        if ($action === 'decrypt') {
            $id = (int)($_POST['record_id'] ?? 0);
            if ($id > 0) {
                $db  = getDB();
                $st  = $db->prepare("SELECT * FROM vault_data WHERE id = ?");
                $st->execute([$id]);
                $row = $st->fetch();

                if ($row) {
                    $plain   = VaultCrypto::aesDecrypt($row['encrypted_text'], $row['iv']);
                    $sigOk   = VaultCrypto::rsaVerify($plain, $row['signature'] ?? '');
                    $hashOk  = VaultCrypto::sha256($plain) === $row['hash_sha256'];

                    $message = "success:✅ Тайлах амжилттай!";
                    $result  = [
                        'plaintext'  => $plain,
                        'label'      => $row['label'],
                        'sig_valid'  => $sigOk,
                        'hash_valid' => $hashOk,
                    ];
                } else {
                    $message = "error:❌ Бүртгэл олдсонгүй!";
                }
            }
        }

        if ($action === 'hash') {
            $text = $_POST['hash_input'] ?? '';
            if ($text) {
                $message = "success:✅ Hash тооцоолсон!";
                $result  = [
                    'md5'    => VaultCrypto::md5Hash($text),
                    'sha256' => VaultCrypto::sha256($text),
                    'sha512' => VaultCrypto::sha512($text),
                    'hmac'   => VaultCrypto::hmac($text),
                    'bcrypt' => VaultCrypto::hashPassword($text),
                ];
            }
        }

        if ($action === 'genpwd') {
            $len     = min(64, max(8, (int)($_POST['pwd_length'] ?? 16)));
            $message = "success:✅ Нууц үг үүслээ!";
            $result  = ['password' => VaultCrypto::generatePassword($len)];
        }

    } catch (Exception $e) {
        $message = "error:❌ Алдаа: " . htmlspecialchars($e->getMessage());
    }
}
$records = [];
try {
    $db      = getDB();
    $records = $db->query("SELECT id, label, hash_sha256, created_at FROM vault_data ORDER BY id DESC LIMIT 20")->fetchAll();
} catch (Exception $e) {}

[$msgType, $msgText] = str_contains($message, ':') ? explode(':', $message, 2) : ['', $message];
?>
<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔐 The Vault — Cryptography Demo</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    min-height: 100vh;
    line-height: 1.6;
}

.header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 20px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
}
.header-icon { font-size: 36px; }
.header h1   { font-size: 24px; color: #f0f6fc; font-weight: 600; }
.header p    { font-size: 13px; color: #8b949e; }

.container { max-width: 1100px; margin: 0 auto; padding: 24px 20px; }
.grid      { display: grid; grid-template-columns: 1fr 300px; gap: 24px; }

.tabs     { display: flex; gap: 4px; margin-bottom: 20px; flex-wrap: wrap; }
.tab-btn  {
    padding: 8px 18px; border-radius: 8px; border: 1px solid #30363d;
    background: #161b22; color: #8b949e; cursor: pointer;
    font-size: 14px; text-decoration: none; transition: all .2s;
}
.tab-btn:hover  { border-color: #58a6ff; color: #58a6ff; }
.tab-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }

.card       { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; margin-bottom: 20px; }
.card-title { font-size: 16px; font-weight: 600; color: #f0f6fc; margin-bottom: 16px; }

label { display: block; font-size: 13px; color: #8b949e; margin-bottom: 6px; }

input[type=text], input[type=number], textarea, select {
    width: 100%; padding: 10px 14px; border-radius: 8px;
    border: 1px solid #30363d; background: #0d1117; color: #c9d1d9;
    font-size: 14px; font-family: inherit; margin-bottom: 14px;
    transition: border-color .2s;
}
input:focus, textarea:focus, select:focus { outline: none; border-color: #58a6ff; }
textarea { resize: vertical; min-height: 90px; font-family: 'Consolas', monospace; }

.btn         { padding: 10px 24px; border-radius: 8px; border: none; font-size: 14px; font-weight: 500; cursor: pointer; transition: all .2s; }
.btn-green   { background: #238636; color: #fff; }
.btn-green:hover { background: #2ea043; }
.btn-blue    { background: #1f6feb; color: #fff; }
.btn-blue:hover  { background: #388bfd; }

.alert         { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; border: 1px solid; }
.alert-success { background: #0f2819; border-color: #238636; color: #3fb950; }
.alert-error   { background: #280d0d; border-color: #f85149; color: #f85149; }

.result-box   { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-top: 16px; }
.result-row   { margin-bottom: 12px; }
.result-label { color: #58a6ff; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px; }
.result-value { word-break: break-all; color: #7ee787; background: #13181e; padding: 8px 10px; border-radius: 6px; font-size: 12px; font-family: 'Consolas', monospace; }
.result-value.purple { color: #d2a8ff; }
.result-value.white  { color: #f0f6fc; font-size: 16px; letter-spacing: 2px; }

.badge       { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.badge-green { background: #0f2819; color: #3fb950; border: 1px solid #238636; }
.badge-red   { background: #280d0d; color: #f85149; border: 1px solid #da3633; }

.table-wrap { overflow-x: auto; }
table       { width: 100%; border-collapse: collapse; font-size: 13px; }
th { background: #21262d; color: #8b949e; padding: 10px 12px; text-align: left; font-weight: 500; }
td { padding: 10px 12px; border-top: 1px solid #21262d; }
tr:hover td { background: #1c2128; }

.info-item    { margin-bottom: 14px; }
.info-item h4 { font-size: 13px; color: #f0f6fc; margin-bottom: 4px; }
.info-item p  { font-size: 12px; color: #8b949e; }
.tag { display: inline-block; background: #21262d; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-size: 11px; color: #8b949e; margin: 2px; }

code { background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 12px; color: #7ee787; }

@media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>

<div class="header">
    <div class="header-icon">🔐</div>
    <div>
        <h1>The Vault</h1>
        <p>Data Protection &amp; Cryptography Demo — PHP 8.2 + XAMPP + MySQL</p>
    </div>
</div>

<div class="container">

<?php if ($msgText): ?>
<div class="alert alert-<?= $msgType === 'success' ? 'success' : 'error' ?>">
    <?= htmlspecialchars($msgText) ?>
</div>
<?php endif; ?>

<div class="tabs">
    <a href="?tab=encrypt" class="tab-btn <?= $tab==='encrypt' ? 'active':'' ?>">🔒 Шифрлэх</a>
    <a href="?tab=decrypt" class="tab-btn <?= $tab==='decrypt' ? 'active':'' ?>">🔓 Тайлах</a>
    <a href="?tab=hash"    class="tab-btn <?= $tab==='hash'    ? 'active':'' ?>">🔑 Hash</a>
    <a href="?tab=pwdgen"  class="tab-btn <?= $tab==='pwdgen'  ? 'active':'' ?>">🎲 Нууц үг</a>
    <a href="?tab=records" class="tab-btn <?= $tab==='records' ? 'active':'' ?>">📋 Бүртгэл</a>
</div>

<div class="grid">
<div>

<?php if ($tab === 'encrypt'): ?>

<div class="card">
    <div class="card-title">🔒 AES-256-CBC Шифрлэлт + RSA Гарын үсэг</div>
    <form method="POST">
        <input type="hidden" name="csrf"   value="<?= $_SESSION['csrf_token'] ?>">
        <input type="hidden" name="action" value="encrypt">
        <label>Өгөгдлийн нэр</label>
        <input type="text" name="label" placeholder="Жш: Нийслэлийн нууц мэдээлэл" required>
        <label>Шифрлэх текст</label>
        <textarea name="plaintext" placeholder="Нууц мэдээллээ энд бичнэ үү..." required></textarea>
        <button class="btn btn-green">🔒 Шифрлэж хадгалах</button>
    </form>

    <?php if ($result && $tab === 'encrypt'): ?>
    <div class="result-box">
        <div class="result-row">
            <div class="result-label">🔐 Шифрлэгдсэн текст (AES-256-CBC)</div>
            <div class="result-value purple"><?= htmlspecialchars($result['cipher']) ?></div>
        </div>
        <div class="result-row">
            <div class="result-label">🎯 IV (Initialization Vector)</div>
            <div class="result-value"><?= htmlspecialchars($result['iv']) ?></div>
        </div>
        <div class="result-row">
            <div class="result-label">🔑 SHA-256 Hash</div>
            <div class="result-value"><?= $result['sha256'] ?></div>
        </div>
        <div class="result-row">
            <div class="result-label">⚠️ MD5 Hash (харьцуулалтын зорилгоор)</div>
            <div class="result-value"><?= $result['md5'] ?></div>
        </div>
        <div class="result-row">
            <div class="result-label">✍️ RSA Гарын үсэг (SHA256withRSA)</div>
            <div class="result-value purple"><?= htmlspecialchars(substr($result['signature'],0,100)) ?>...</div>
        </div>
    </div>
    <?php endif; ?>
</div>

<?php elseif ($tab === 'decrypt'): ?>

<div class="card">
    <div class="card-title">🔓 Шифрлэгдсэн өгөгдөл тайлах</div>
    <?php if (empty($records)): ?>
        <p style="color:#8b949e">Эхлээд "Шифрлэх" хэсэгт өгөгдөл хадгална уу.</p>
    <?php else: ?>
    <form method="POST">
        <input type="hidden" name="csrf"   value="<?= $_SESSION['csrf_token'] ?>">
        <input type="hidden" name="action" value="decrypt">
        <label>Тайлах бүртгэл сонгох</label>
        <select name="record_id">
            <?php foreach ($records as $r): ?>
            <option value="<?= $r['id'] ?>">[#<?= $r['id'] ?>] <?= htmlspecialchars($r['label']) ?></option>
            <?php endforeach; ?>
        </select>
        <button class="btn btn-blue">🔓 Тайлах &amp; Баталгаажуулах</button>
    </form>

    <?php if ($result && $tab === 'decrypt'): ?>
    <div class="result-box">
        <div class="result-row">
            <div class="result-label">📄 Тайлагдсан текст — <?= htmlspecialchars($result['label']) ?></div>
            <div class="result-value white"><?= htmlspecialchars($result['plaintext']) ?></div>
        </div>
        <div class="result-row" style="display:flex;gap:12px;align-items:center">
            <span>RSA Гарын үсэг:</span>
            <span class="badge <?= $result['sig_valid'] ? 'badge-green':'badge-red' ?>">
                <?= $result['sig_valid'] ? '✅ Хүчинтэй':'❌ Буруу' ?>
            </span>
            <span>SHA-256 Бүрэн бүтэн байдал:</span>
            <span class="badge <?= $result['hash_valid'] ? 'badge-green':'badge-red' ?>">
                <?= $result['hash_valid'] ? '✅ Бүрэн бүтэн':'❌ Гэмтсэн' ?>
            </span>
        </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>
</div>

<?php elseif ($tab === 'hash'): ?>

<div class="card">
    <div class="card-title">🔑 Hash Функцүүд харьцуулах</div>
    <form method="POST">
        <input type="hidden" name="csrf"   value="<?= $_SESSION['csrf_token'] ?>">
        <input type="hidden" name="action" value="hash">
        <label>Hash хийх текст</label>
        <input type="text" name="hash_input" placeholder="Жш: нууц123" required>
        <button class="btn btn-blue">🔑 Hash тооцоолох</button>
    </form>

    <?php if ($result && $tab === 'hash'): ?>
    <div class="result-box">
        <?php
        $items = [
            ['⚠️ MD5 (32 тэмдэгт — АЮУЛГҮЙ БУС)',  $result['md5'],    ''],
            ['✅ SHA-256 (64 тэмдэгт)',               $result['sha256'], ''],
            ['✅ SHA-512 (128 тэмдэгт)',              $result['sha512'], 'purple'],
            ['🔐 HMAC-SHA256 (нууц түлхүүртэй)',      $result['hmac'],   ''],
            ['🔐 bcrypt cost=12 (нууц үгийн hash)',   $result['bcrypt'], 'purple'],
        ];
        foreach ($items as [$label, $val, $cls]): ?>
        <div class="result-row">
            <div class="result-label"><?= $label ?></div>
            <div class="result-value <?= $cls ?>"><?= htmlspecialchars($val) ?></div>
        </div>
        <?php endforeach; ?>
        <p style="color:#8b949e;font-size:12px;margin-top:8px">💡 bcrypt нь нууц үгийн hash-д хамгийн тохиромжтой. MD5 ашиглаж болохгүй!</p>
    </div>
    <?php endif; ?>
</div>

<?php elseif ($tab === 'pwdgen'): ?>

<div class="card">
    <div class="card-title">🎲 Хүчтэй Нууц үг Үүсгэгч</div>
    <form method="POST">
        <input type="hidden" name="csrf"   value="<?= $_SESSION['csrf_token'] ?>">
        <input type="hidden" name="action" value="genpwd">
        <label>Урт (8–64 тэмдэгт)</label>
        <input type="number" name="pwd_length" value="16" min="8" max="64">
        <button class="btn btn-green">🎲 Нууц үг үүсгэх</button>
    </form>

    <?php if ($result && $tab === 'pwdgen'): ?>
    <div class="result-box">
        <div class="result-label">Үүссэн нууц үг</div>
        <div class="result-value white"><?= htmlspecialchars($result['password']) ?></div>
        <p style="color:#8b949e;font-size:12px;margin-top:8px">
            💡 PHP-н <code>random_bytes()</code> + <code>random_int()</code> — Cryptographically Secure PRNG ашигласан
        </p>
    </div>
    <?php endif; ?>
</div>

<?php elseif ($tab === 'records'): ?>

<div class="card">
    <div class="card-title">📋 Хадгалагдсан Шифрлэгдсэн Өгөгдлүүд</div>
    <?php if (empty($records)): ?>
        <p style="color:#8b949e">Одоогоор бүртгэл байхгүй.</p>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead>
                <tr><th>#</th><th>Нэр</th><th>SHA-256 (эхний 20)</th><th>Огноо</th><th></th></tr>
            </thead>
            <tbody>
                <?php foreach ($records as $r): ?>
                <tr>
                    <td><?= $r['id'] ?></td>
                    <td><?= htmlspecialchars($r['label']) ?></td>
                    <td style="font-family:monospace;font-size:11px;color:#8b949e"><?= substr($r['hash_sha256'],0,20) ?>...</td>
                    <td style="font-size:12px;color:#8b949e"><?= $r['created_at'] ?></td>
                    <td><a href="?tab=decrypt" style="color:#58a6ff;font-size:12px">Тайлах</a></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>

</div>

<div>
    <div class="card">
        <div class="card-title" style="font-size:14px">📚 Алгоритмууд</div>
        <div class="info-item">
            <h4>🔒 AES-256-CBC</h4>
            <p>Symmetric шифрлэлт. 256-bit түлхүүр, санамсаргүй IV.</p>
            <div><span class="tag">Symmetric</span><span class="tag">Fast</span><span class="tag">Secure</span></div>
        </div>
        <div class="info-item">
            <h4>✍️ RSA-2048</h4>
            <p>Asymmetric гарын үсэг. Private→sign, Public→verify.</p>
            <div><span class="tag">Asymmetric</span><span class="tag">Signature</span></div>
        </div>
        <div class="info-item">
            <h4>🔑 SHA-256</h4>
            <p>256-bit one-way hash. Бүрэн бүтэн байдал шалгана.</p>
            <div><span class="tag">One-way</span><span class="tag">Integrity</span></div>
        </div>
        <div class="info-item">
            <h4>🔐 bcrypt</h4>
            <p>Нууц үгийн hash. Cost 12, өөртөө salt агуулдаг.</p>
            <div><span class="tag">Password</span><span class="tag">Adaptive</span></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title" style="font-size:14px">🛡️ Аюулгүй байдал</div>
        <div style="font-size:12px;color:#8b949e;line-height:2">
            ✅ CSRF токен хамгаалалт<br>
            ✅ PDO Prepared statements<br>
            ✅ htmlspecialchars() XSS<br>
            ✅ random_bytes() CSPRNG<br>
            ✅ RSA гарын үсэг<br>
            ✅ bcrypt нууц үг hash<br>
            ⚠️ Demo — HTTPS хэрэглэ production-д
        </div>
    </div>

    <div class="card">
        <div class="card-title" style="font-size:14px">⚡ PHP Функцүүд</div>
        <div style="font-size:11px;line-height:2.2">
            <code>openssl_encrypt()</code><br>
            <code>openssl_decrypt()</code><br>
            <code>openssl_pkey_new()</code><br>
            <code>openssl_sign()</code><br>
            <code>openssl_verify()</code><br>
            <code>password_hash()</code><br>
            <code>random_bytes()</code><br>
            <code>hash_hmac()</code>
        </div>
    </div>
</div>

</div>
</div>
</body>
</html>
