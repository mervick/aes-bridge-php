#!/usr/bin/env php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use AesBridge\Cbc;
use AesBridge\Gcm;
use AesBridge\Legacy;


// --- CLI Parsing Logic ---
$options = [
    'action'     => null,
    'mode'       => null,
    'data'       => null,
    'passphrase' => null,
    'b64'        => false,
];

for ($i = 1; $i < count($argv); $i++) {
    switch ($argv[$i]) {
        case 'encrypt':
        case 'decrypt':
            $options['action'] = $argv[$i];
            break;
        case '--mode':
            $options['mode'] = $argv[++$i];
            break;
        case '--data':
            $options['data'] = $argv[++$i];
            break;
        case '--passphrase':
            $options['passphrase'] = $argv[++$i];
            break;
        case '--b64':
            $options['b64'] = true;
            break;
        case '-h':
        case '--help':
            echo "Usage: php " . basename(__FILE__) . " <action> --mode MODE --data DATA --passphrase PASSPHRASE [--b64]\n";
            echo "Actions: encrypt, decrypt\n";
            echo "Modes: cbc, gcm, legacy\n";
            echo "--data: Data to encrypt (UTF-8 string) or decrypt (base64 string).\n";
            echo "--passphrase: Passphrase for key derivation.\n";
            echo "--b64: Accept base64 encoded input and returns base64 encoded output.\n";
            exit(0);
    }
}

if (!in_array($options['action'], ['encrypt', 'decrypt'])) {
    fwrite(STDERR, "Error: Action must be 'encrypt' or 'decrypt'.\n");
    exit(1);
}

if (!$options['mode']) {
    fwrite(STDERR, "Error: Missing required option --mode.\n");
    exit(1);
}

if (!in_array($options['mode'], ['cbc', 'gcm', 'legacy'])) {
    fwrite(STDERR, "Error: Invalid mode. Must be 'cbc', 'gcm', or 'legacy'.\n");
    exit(1);
}

if (!$options['data']) {
    fwrite(STDERR, "Error: Missing required option --data.\n");
    exit(1);
}

if (!$options['passphrase']) {
    fwrite(STDERR, "Error: Missing required option --passphrase.\n");
    exit(1);
}

try {
    $data_input = $options['data'];
    $result = null;

    if ($options['action'] === 'encrypt') {
        $data_to_process = $options['b64'] ? base64_decode($data_input) : $data_input;
        if ($data_to_process === false) {
            throw new Exception('Failed to base64 decode input data.');
        }

        switch ($options['mode']) {
            case 'cbc':
                $result = Cbc::encrypt($data_to_process, $options['passphrase']);
                break;
            case 'gcm':
                $result = Gcm::encrypt($data_to_process, $options['passphrase']);
                break;
            case 'legacy':
                $result = Legacy::encrypt($data_to_process, $options['passphrase']);
                break;
        }
    } elseif ($options['action'] === 'decrypt') {
        switch ($options['mode']) {
            case 'cbc':
                $decrypted = Cbc::decrypt($data_input, $options['passphrase']);
                $result = $options['b64'] ? base64_encode($decrypted) : $decrypted;
                break;
            case 'gcm':
                $decrypted = Gcm::decrypt($data_input, $options['passphrase']);
                $result = $options['b64'] ? base64_encode($decrypted) : $decrypted;
                break;
            case 'legacy':
                $decrypted = Legacy::decrypt($data_input, $options['passphrase']);
                $result = $options['b64'] ? base64_encode($decrypted) : $decrypted;
                break;
        }
    }

    echo $result . "\n";

} catch (Exception $e) {
    fwrite(STDERR, "An unexpected error occurred: " . $e->getMessage() . "\n");
    exit(1);
}
