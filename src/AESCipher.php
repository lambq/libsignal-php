<?php
namespace Libsignal;

use Libsignal\exceptions\InvalidKeyException;

class AESCipher
{
    private string $max_size;
    private string $key;
    private string $cipher;

    public function __construct(string $key, string $cipher = 'aes-256-gcm')
    {
        $len            = strlen($key);
        if ($len == 16 || $len == 24 || $len == 32)
        {
            $this->key      = $key;
            $this->cipher   = $cipher;
        } else {
            throw new InvalidKeyException('AESCipher $key长度: ' . $len);
        }
        $this->max_size     = 2**31 - 1;
    }
    /**
     * 原始版本的输入密码，附加认证字符串，初始向量的aes256gcm加密函数
     * original_aes256gcm_encrypt('text', 'password', '附加认证字符', '初始向量');
     * $data 加密文本
     * $password 密钥 byte
     * $additional 附加认证字符
     * $nonce   初始向量
     */
    public function encrypt($data, $nonce = '', $additional = '')
    {
        if (strlen($data) > $this->max_size)
        {
            throw new InvalidKeyException('AESCipher $data 长度 > $this->max_size :' . strlen($data));
        }
        $func_name  = 'sodium_crypto_aead_aes256gcm_is_available';
        if (function_exists($func_name) && $func_name()) {
            $endata = sodium_crypto_aead_aes256gcm_encrypt($data, $additional, $nonce, $this->key);
        } else {
            $func_name = 'openssl_encrypt';
            $tag = null;
            $endata = $func_name($data, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $nonce, $tag, $additional, 16);
            $endata .= $tag;
        }
        return $endata;
    }

//    public function encrypt(string $plaintext): string
//    {
//        if len(data) > self._MAX_SIZE or len(associated_data) > self._MAX_SIZE:
//            # This is OverflowError to match what cffi would raise
//            raise OverflowError(
//            "Data or associated data too long. Max 2**31 - 1 bytes"
//        )
//
//        $iv         = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
//        $ciphertext = sodium_crypto_aead_aes256gcm_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);
//        print_r($ciphertext);die();
//        return base64_encode($iv . $ciphertext);
//    }


    function aes256gcm_encrypt(string $data, string $keygen, string $aad = ''): array
    {
        $iv = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $encrypt = sodium_crypto_aead_aes256gcm_encrypt($data, $aad, $iv, $keygen); // 包含密文、tag
        return [
            'iv'          => sodium_bin2base64($iv, SODIUM_BASE64_VARIANT_ORIGINAL),
            'aad'         => sodium_bin2base64($aad, SODIUM_BASE64_VARIANT_ORIGINAL),
            'cipher_text' => sodium_bin2base64($encrypt, SODIUM_BASE64_VARIANT_ORIGINAL),
        ];
    }

    public function decrypt(string $encryptedData): string
    {
        $data = base64_decode($encryptedData);
        $ivlen = openssl_cipher_iv_length($this->cipher);
        $iv = substr($data, 0, $ivlen);
        $ciphertext = substr($data, $ivlen);

        return openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);
    }
}
