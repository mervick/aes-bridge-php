<?php
/**
 * This file is part of AesBridge - modern cross-language AES encryption library
 * Repository: https://github.com/mervick/aes-bridge
 *
 * Copyright Andrey Izman (c) 2018-2025 <izmanw@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

 namespace AesBridge;

/**
 * Generates AES and HMAC keys from a password and salt using PBKDF2.
 *
 * @param string $password Password as a binary string.
 * @param string $salt Salt as a binary string (16 bytes).
 * @return array Array containing AES key (32 bytes) and HMAC key (32 bytes).
 * @throws \Exception If PBKDF2 fails to generate enough key material.
 */
function derive_keys(string $password, string $salt): array {
    $key_material = hash_pbkdf2('sha256', $password, $salt, 100000, 64, true);
    return [
        substr($key_material, 0, 32),
        substr($key_material, 32, 32),
    ];
}

/**
 * Class Cbc
 *
 * This class provides functionality for encrypting and decrypting data using AES-256 in CBC mode
 * with HMAC authentication. It uses PBKDF2 for key derivation to ensure robust security and
 * OpenSSL for encryption and decryption operations. The class supports both binary and base64
 * encoded data formats.
 *
 * @package AesBridge
 */
class Cbc implements EncryptionInterface
{
    /**
     * Encrypts data using AES-256 in CBC mode with HMAC authentication.
     *
     * @param string $plaintext Data to encrypt (string or binary).
     * @param string $password Encryption password (string or binary).
     * @return string Encrypted data in the format: salt (16 bytes) + IV (16 bytes) +
     * ciphertext (variable length) + HMAC tag (32 bytes).
     * @throws \Exception On encryption errors or random generation failures.
     */
    public static function encryptBin(string $plaintext, string $password): string {
        $salt = Utils::generate_random(16);
        $iv = Utils::generate_random(16);

        [$aes_key, $hmac_key] = derive_keys($password, $salt);

        $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $aes_key, OPENSSL_RAW_DATA, $iv);
        $tag = hash_hmac('sha256', $iv . $ciphertext, $hmac_key, true);

        return $salt . $iv . $ciphertext . $tag;
    }

    /**
     * Decrypts data encrypted with encrypt_bin().
     *
     * @param string $data Encrypted data in the format from encrypt_cbc_bin():
     * salt (16) + IV (16) + ciphertext (N) + HMAC (32).
     * @param string $password Password used for encryption.
     * @return string Decrypted data.
     * @throws \Exception On invalid HMAC, decryption errors, or invalid data format.
     */
    public static function decryptBin(string $data, string $password): string {
        $salt = substr($data, 0, 16);
        $iv = substr($data, 16, 16);
        $tag = substr($data, -32);
        $ciphertext = substr($data, 32, -32);

        [$aes_key, $hmac_key] = derive_keys($password, $salt);

        $expected_tag = hash_hmac('sha256', $iv . $ciphertext, $hmac_key, true);
        if (!hash_equals($expected_tag, $tag)) {
            throw new \Exception("Invalid HMAC");
        }

        return openssl_decrypt($ciphertext, 'aes-256-cbc', $aes_key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Encrypts data and returns the result encoded in base64.
     *
     * @param string $data Data to encrypt.
     * @param string $password Password for encryption.
     * @return string Encrypted data in base64.
     */
    public static function encrypt(string $data, string $password): string {
        return base64_encode(Cbc::encryptBin($data, $password));
    }

    /**
     * Decrypts base64-encoded data encrypted with encrypt().
     *
     * @param string $data Encrypted data in base64.
     * @param string $password Password for decryption.
     * @return string Decrypted data.
     * @throws \Exception On invalid HMAC, decryption errors, or invalid data format.
     */
    public static function decrypt(string $data, string $password): string {
        return Cbc::decryptBin(base64_decode($data), $password);
    }
}
