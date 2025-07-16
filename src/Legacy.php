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


const BLOCK_SIZE = 16;
const KEY_LEN = 32;
const IV_LEN = 16;

/**
 * OpenSSL-compatible key and IV derivation from password and salt using MD5
 * @param string $password
 * @param string $salt
 * @return array [string $key, string $iv]
 */
function derive_key_and_iv(string $password, string $salt): array
{
    $d = '';
    $d_i = '';
    while (strlen($d) < KEY_LEN + IV_LEN) {
        $d_i = md5($d_i . $password . $salt, true);
        $d .= $d_i;
    }
    return [substr($d, 0, KEY_LEN), substr($d, KEY_LEN, IV_LEN)];
}

/**
 * Legacy AES-256-CBC encryptor and decryptor
 *
 * This class implements the legacy AES Everywhere encryption and decryption
 * algorithm, which is compatible with OpenSSL. The class is kept for backward
 * compatibility only and is not recommended for new applications.
 */
class Legacy implements EncryptionInterface
{
    /**
     * Encrypt plaintext using AES-256-CBC with OpenSSL-compatible output
     * Format: Salted__ + salt + ciphertext
     * @param string $raw
     * @param string $passphrase
     * @return string base64-encoded ciphertext
     */
    public static function encrypt(string $raw, string $passphrase): string
    {
        $salt = Utils::generate_random(8);
        [$key, $iv] = derive_key_and_iv($passphrase, $salt);
        $ciphertext = openssl_encrypt($raw, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode("Salted__" . $salt . $ciphertext);
    }

    /**
     * Decrypt base64-encoded ciphertext using AES-256-CBC with OpenSSL-compatible format
     * @param string $enc
     * @param string $passphrase
     * @return string
     */
    public static function decrypt(string $enc, string $passphrase): string
    {
        $data = base64_decode($enc);
        if (substr($data, 0, 8) !== "Salted__") {
            return '';
        }
        $salt = substr($data, 8, 8);
        [$key, $iv] = derive_key_and_iv($passphrase, $salt);
        $ciphertext = substr($data, 16);
        return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    }
}
