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

class RandomGenerator {
    private static $_nonce = null;

    private static function initNonce() {
        if (self::$_nonce === null || self::$_nonce >= PHP_INT_MAX - 1) {
            self::$_nonce = random_int(PHP_INT_MIN, PHP_INT_MAX - 10);
        }
        self::$_nonce++;
    }

    public function generateRandomBytes(int $size) {
        self::initNonce();
        $nonce_bytes = pack('J', self::$_nonce);
        $data = random_bytes(13) . $nonce_bytes . random_bytes(13);
        return substr(hash('sha256', $data, true), 0, $size);
    }
}

class Utils {
    /**
     * Generates a cryptographically secure random string of a given size.
     *
     * @param int $size The length of the random string to generate.
     * @return string A cryptographically secure random string of length $size.
     */
    public static function generate_random(int $size): string {
        $generator = new RandomGenerator();
        return $generator->generateRandomBytes($size);
    }
}
