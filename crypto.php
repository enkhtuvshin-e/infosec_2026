<?php

require_once __DIR__ . '/config.php';

class VaultCrypto {


    public static function aesEncrypt(string $plaintext): array {
        $iv     = random_bytes(ENCRYPTION_IV_LENGTH);
        $cipher = openssl_encrypt(
            $plaintext, 'aes-256-cbc',
            ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv
        );
        if ($cipher === false)
            throw new RuntimeException("AES шифрлэлт амжилтгүй: " . openssl_error_string());
        return [
            'cipher' => base64_encode($cipher),
            'iv'     => base64_encode($iv),
        ];
    }

    public static function aesDecrypt(string $cipherBase64, string $ivBase64): string {
        $plain = openssl_decrypt(
            base64_decode($cipherBase64), 'aes-256-cbc',
            ENCRYPTION_KEY, OPENSSL_RAW_DATA, base64_decode($ivBase64)
        );
        if ($plain === false)
            throw new RuntimeException("AES тайлах амжилтгүй.");
        return $plain;
    }

    public static function sha256(string $data): string {
        return hash('sha256', $data);
    }

    public static function md5Hash(string $data): string {
        return md5($data);
    }

    public static function sha512(string $data): string {
        return hash('sha512', $data);
    }

    public static function hmac(string $data, string $secret = ENCRYPTION_KEY): string {
        return hash_hmac('sha256', $data, $secret);
    }
    public static function hashPassword(string $password): string {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public static function verifyPassword(string $password, string $hash): bool {
        return password_verify($password, $hash);
    }

    public static function generateRSAKeys(): void {
        $keyDir = __DIR__ . '/keys';
        if (!is_dir($keyDir)) mkdir($keyDir, 0700, true);

        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'digest_alg'       => 'sha256',
            'config'           => OPENSSL_CNF,
        ];

        $res = openssl_pkey_new($config);
        if ($res === false)
            throw new RuntimeException("RSA key үүсгэж чадсангүй: " . openssl_error_string());

        $privateKey = '';
        if (!openssl_pkey_export($res, $privateKey, null, $config))
            throw new RuntimeException("Private key export амжилтгүй: " . openssl_error_string());

        $details = openssl_pkey_get_details($res);
        if ($details === false)
            throw new RuntimeException("Key details авч чадсангүй.");

        file_put_contents(RSA_PRIVATE_KEY_FILE, $privateKey);
        file_put_contents(RSA_PUBLIC_KEY_FILE,  $details['key']);
    }

    public static function rsaSign(string $data): string {
        if (!file_exists(RSA_PRIVATE_KEY_FILE)) self::generateRSAKeys();
        $privateKey = openssl_pkey_get_private(file_get_contents(RSA_PRIVATE_KEY_FILE));
        if ($privateKey === false)
            throw new RuntimeException("Private key уншиж чадсангүй.");
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256))
            throw new RuntimeException("Гарын үсэг зурж чадсангүй.");
        return base64_encode($signature);
    }

    public static function rsaVerify(string $data, string $signatureBase64): bool {
        if (!file_exists(RSA_PUBLIC_KEY_FILE)) return false;
        $publicKey = openssl_pkey_get_public(file_get_contents(RSA_PUBLIC_KEY_FILE));
        if ($publicKey === false) return false;
        return openssl_verify(
            $data, base64_decode($signatureBase64),
            $publicKey, OPENSSL_ALGO_SHA256
        ) === 1;
    }

    public static function generateToken(int $bytes = 32): string {
        return bin2hex(random_bytes($bytes));
    }

    public static function generatePassword(int $length = 16): string {
        $chars  = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
        $result = '';
        for ($i = 0; $i < $length; $i++)
            $result .= $chars[random_int(0, strlen($chars) - 1)];
        return $result;
    }
}
