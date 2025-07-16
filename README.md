# AesBridge PHP

![Packagist Version](https://img.shields.io/packagist/v/mervick/aes-bridge.svg)
![CI Status](https://github.com/mervick/aes-bridge-php/actions/workflows/codeception.yml/badge.svg)

**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.


This is the **PHP implementation** of the core project.  
👉 Main repository: https://github.com/mervick/aes-bridge

## Features

- 🔐 AES-256 encryption in GCM (recommended) and CBC modes
- 🌍 Cross-Platform: Consistent behavior across different languages
- 📦 Compact binary format or base64 output
- ✅ HMAC Integrity: CBC mode includes HMAC verification
- 🔄 Backward Compatible: Supports legacy AES Everywhere format

## Requirements

- PHP 7.4 or higher
- OpenSSL extension

## Installation

```sh
composer require mervick/aes-bridge:"^2.0"
```

## Basic Usage

```php
use AesBridge\Gcm;
use AesBridge\Cbc;

// encrypt/decrypt using GCM mode (recommended)
$ciphertext = Gcm::encrypt("My secret message", "MyStrongPass")
$plaintext = Gcm::decrypt($ciphertext, "MyStrongPass")

// encrypt/decrypt using CBC mode
$ciphertext = Cbc::encrypt("My secret message", "MyStrongPass")
$plaintext = Cbc::decrypt($ciphertext, "MyStrongPass")

```


## API Reference

### GCM Mode (recommended)

- `Gcm::encrypt(data, passphrase)`  
  Encrypts a string using AES-GCM.
  **Returns:** base64-encoded string.

- `Gcm::decrypt(ciphertext, passphrase)`  
  Decrypts a base64-encoded string encrypted with `Gcm::encrypt`.

- `Gcm::encryptBin(data, passphrase)`  
  Returns encrypted binary data using AES-GCM.

- `Gcm::decryptBin(ciphertext, passphrase)`  
  Decrypts binary data encrypted with `Gcm::encryptBin`.

### CBC Mode

- `Cbc::encrypt(data, passphrase)`  
  Encrypts a string using AES-CBC. 
  HMAC is used for integrity verification.  
  **Returns:** base64-encoded string.  

- `Cbc::decrypt(ciphertext, passphrase)`  
  Decrypts a base64-encoded string encrypted with `Cbc::encrypt` and verifies HMAC.

- `Cbc::encryptBin(data, passphrase)`  
  Returns encrypted binary data using AES-CBC with HMAC.

- `Cbc::decryptBin(ciphertext, passphrase)`  
  Decrypts binary data encrypted with `Cbc::encryptBin` and verifies HMAC.

### Legacy Compatibility

⚠️ These functions are kept for backward compatibility only.
Their usage is strongly discouraged in new applications.

- `Legacy::encrypt(data, passphrase)`  
  Encrypts a string in the legacy AES Everywhere format.  

- `Legacy::decrypt(ciphertext, passphrase)`  
  Decrypts a string encrypted in the legacy AES Everywhere format.


## Error Handling

All methods throw exceptions for:

- Invalid input data
- Incorrect passwords
- Corrupted ciphertext
- HMAC verification failures (CBC mode)
