<?php

namespace AesBridge\Tests\unit;

use Codeception\Test\Unit;
use UnitTester;

use AesBridge\Gcm;
use AesBridge\Cbc;
use AesBridge\Legacy;

class AesBridgeTest extends Unit
{
    /**
     * @var \UnitTester
     */
    protected $tester;

    protected static $testData;

    public static function readData()
    {
        if (self::$testData) {
            return self::$testData;
        }
        $jsonDataPath = codecept_data_dir('test_data.json');
        $jsonData = file_get_contents($jsonDataPath);
        self::$testData = json_decode($jsonData, true);
        return self::$testData;
    }

    public static function provideTestCases(): array
    {
        $data = self::readData();
        $return = [];

        foreach ($data['testdata']['plaintext'] as $str) {
            $return[] = [$str];
        }
        foreach ($data['testdata']['hex'] as $hex) {
            $return[] = [hex2bin($hex)];
        }

        $return[] = [str_repeat('A', 1000)];

        return $return;
    }

    public static function provideDecyptionCases(): array
    {
        $data = self::readData();
        $return = [];

        foreach ($data['decrypt'] as $case) {
            $return[] = [
                $case['id'],
                $case['plaintext'] ?? hex2bin($case['hex']),
                $case['passphrase'],
                $case['encrypted-cbc'] ?? null,
                $case['encrypted-gcm'] ?? null,
                $case['encrypted-legacy'] ?? null,
            ];
        }

        return $return;
    }

    /**
     * @dataProvider provideTestCases
     */
    public function testCbcEncryptionDecryption($plaintext)
    {
        $encrypted = Cbc::encrypt($plaintext, $plaintext);
        $plaintextDemo = $plaintext;
        if (strlen($plaintext) > 20) {
            $plaintextDemo = substr($plaintext, 0, 20) . '...';
        }
        $this->assertNotEmpty($encrypted, "Encryption failed");
        $decrypted = Cbc::decrypt($encrypted, $plaintext);
        $this->assertEquals($plaintext, $decrypted, "Decryption failed");
    }

    /**
     * @dataProvider provideTestCases
     */
    public function testGcmEncryptionDecryption($plaintext)
    {
        $encrypted = Gcm::encrypt($plaintext, $plaintext);
        $plaintextDemo = $plaintext;
        if (strlen($plaintext) > 20) {
            $plaintextDemo = substr($plaintext, 0, 20) . '...';
        }
        $this->assertNotEmpty($encrypted, "Encryption failed");
        $decrypted = Gcm::decrypt($encrypted, $plaintext);
        $this->assertEquals($plaintext, $decrypted, "Decryption failed");
    }

    /**
     * @dataProvider provideTestCases
     */
    public function testLegacyEncryptionDecryption($plaintext)
    {
        $encrypted = Legacy::encrypt($plaintext, $plaintext);
        $plaintextDemo = $plaintext;
        if (strlen($plaintext) > 20) {
            $plaintextDemo = substr($plaintext, 0, 20) . '...';
        }
        $this->assertNotEmpty($encrypted, "Encryption failed");
        $decrypted = Legacy::decrypt($encrypted, $plaintext);
        $this->assertEquals($plaintext, $decrypted, "Decryption failed");
    }

    /**
     * @dataProvider provideDecyptionCases
     */
    public function testCbcDecryptionWithTestData($id, $plaintext, $passphrase, $encryptedCbc, $encryptedGcm, $encryptedLegacy)
    {
        if ($encryptedCbc) {
            $decrypted = Cbc::decrypt($encryptedCbc, $passphrase);
            $this->assertEquals($plaintext, $decrypted, "CBC Decryption failed for case: $id");
        }
    }

    /**
     * @dataProvider provideDecyptionCases
     */
    public function testGcmDecryptionWithTestData($id, $plaintext, $passphrase, $encryptedCbc, $encryptedGcm, $encryptedLegacy)
    {
        if ($encryptedGcm) {
            $decrypted = Gcm::decrypt($encryptedGcm, $passphrase);
            $this->assertEquals($plaintext, $decrypted, "GCM Decryption failed for case: $id");
        }
    }

    /**
     * @dataProvider provideDecyptionCases
     */
    public function testLegacyDecryptionWithTestData($id, $plaintext, $passphrase, $encryptedCbc, $encryptedGcm, $encryptedLegacy)
    {
        if ($encryptedLegacy) {
            $decrypted = Legacy::decrypt($encryptedLegacy, $passphrase);
            $this->assertEquals($plaintext, $decrypted, "Legacy Decryption failed for case: $id");
        }
    }
}
