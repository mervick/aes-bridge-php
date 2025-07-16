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
 * Derives an AES key from a password and salt using PBKDF2.
 *
 * @param string $password The password used to generate the key.
 * @param string $salt The salt value used in key derivation (16 bytes).
 * @return string A 32-byte AES key derived from the password and salt.
 */
function derive_key(string $password, string $salt): string {
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}

/**
 * Class Gcm
 *
 * This class provides methods for encrypting and decrypting data using AES-256 in GCM mode.
 * The class supports both binary and base64 encoded data formats.
 *
 * @package AesBridge
 */
class Gcm implements EncryptionInterface
{
    /**
     * Encrypts data using AES-256 in GCM mode.
     *
     * @param string $plaintext Data to encrypt (string or binary).
     * @param string $password Encryption password (string or binary).
     * @return string Encrypted data in the format: salt (16 bytes) + nonce (12 bytes) +
     * ciphertext (variable length) + tag (16 bytes).
     */
    function encryptBin(string $plaintext, string $password): string {
        $salt = Utils::generate_random(16);
        $nonce = Utils::generate_random(12);
        $key = derive_key($password, $salt);

        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);

        return $salt . $nonce . $ciphertext . $tag;
    }

    /**
     * Decrypts data encrypted with encrypt_bin().
     *
     * @param string $data Encrypted data in the format: salt (16 bytes) + nonce (12 bytes) +
     * ciphertext (variable length) + tag (16 bytes).
     * @param string $password Encryption password (string or binary).
     * @return string Decrypted data.
     */
    function decryptBin(string $data, string $password): string {
        $salt = substr($data, 0, 16);
        $nonce = substr($data, 16, 12);
        $tag = substr($data, -16);
        $ciphertext = substr($data, 28, -16);

        $key = derive_key($password, $salt);

        return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    }

    /**
     * Encrypts data using AES-256 in GCM mode.
     *
     * @param string $plaintext Data to encrypt (string or binary).
     * @param string $password Encryption password (string or binary).
     * @return string Encrypted data in the format: salt (16 bytes) + nonce (12 bytes) +
     * ciphertext (variable length) + tag (16 bytes).
     */
    public static function encrypt(string $plaintext, string $password): string {
        return base64_encode(Gcm::encryptBin($plaintext, $password));
    }

    /**
     * Decrypts data encrypted with encrypt().
     *
     * @param string $data Encrypted data.
     * @param string $password Password used for encryption.
     * @return string Decrypted data.
     */
    public static function decrypt(string $data, string $password): string {
        return Gcm::decryptBin(base64_decode($data), $password);
    }
}
