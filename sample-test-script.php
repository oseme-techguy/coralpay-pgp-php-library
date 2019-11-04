<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Encryption tests script.
 *
 */

/**
 * Require Library
 */
require_once 'CoralPayPGPEncryption.php';

/**
 * Tests encryption abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Oseme Odigie <oseme.odigie@coralpay.com>
 * @copyright 2018-2019 coralpay
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class EncryptTestCase
{
    private $gpg;

    public function __construct() {
        $this->testingEncrypt();
        // $this->testingDecrypt();
    }


    /**
     * Testing the listing of the keys and GPG information
     * @group string
     */
    public function getInfo()
    {
        $options_array = array();
        $this->gpg = new CoralPayPGPEncryption($options_array);
        

        $encryptedData = $this->gpg->getKey($data, $keyId);
        
        print "\n\n";
        print_r($encryptedData . PHP_EOL);
        print "\n\n";
    }

    /**
     * Testing the Encrypt part of the function
     * @group string
     */
    public function testingEncrypt()
    {
        $options_array = array();
        $this->gpg = new CoralPayPGPEncryption($options_array);
        
        $data = '{"username":"userHere","password": "someSecret",' . 
                '"RequestDetails": {"terminalId":"111111","amount":11540,"reference":"1582",' . 
                '"otherInfo": "1111110000001"}}';

        /*
        $data = json_encode(array(
            "reference"=>"10003443",
            "sourceInstitutionId"=>"000500", 
            "mobileNumber"=>"0801158675"
        ));
        */

        $keyId = '4DAFEF32187148DC86FC4FD3F575986890FCABB3BA';

        $encryptedData = $this->gpg->encryptRequest($data, $keyId);
        
        print "\n\n";
        print_r($encryptedData . PHP_EOL);
        print "\n\n";
    }

    /**
     * Testing the Decrypt part of the function
     * @group string
     */
    public function testingDecrypt()
    {
        $options_array = array();
        $this->gpg = new CoralPayPGPEncryption($options_array);
        
        $encryptedData = '85010c03c69c19e7bdf8918f0107ff7c68a0956587c274b67ab61cc201748b60a744667d9509572536bc8b9becdd83586fc9fddadfad2daea3ff4fc85a59f05da564edc9ded880f2f9e257cf68c14dd702c0f8f9a7d3b5a04cb674c692c50d4ac4ca8767313ba9e9b3160c9b6271c978f786f70de1732aa4632db17577072800bfcec4e37aa65a3777b85dbd041c47325554d48570eda432dcc64e893853f8f64c43c22abb1acc35df17449424d96e74653c631b77ac56cf32648a44ccec53b8e502c77e0ea7dfb06ea0e2baff8629b90244e6ce3b6f1ea26e485e58735fb64cdd243b82febc50bc6e54f4a81eacc355738ee067b3834044600ef6c09641ca69ca49d1996db8d3ce64cc2219e13b1ec9ab90e8f48547a685d71c186d5b3fa84b98afec4818a4f1055cd30a7a15f06be5924759db7066ff4486c345fa812582d8870b2d3e7c902f503a75046ec9722e0c169347fe1415427ebcdc2afcf73b7016d200576781f38d5802cc11e9cecd4ae36ef1314609079a128dfacc55e1d7f987ece140ab55d87b4b7ed709feb909448bf409b8a2d451803c3606fc6502c0313dd9140f9ecde02d052c5f2b9bf6f2fba6a8654ce8d72d54e23ddef150';

        $keyId = '11D9890DCE42510F0AD31CC6C69C12E7EDFB9D7B';
        $passphrase = 'your-passphrase-here';
        
        $decryptedData = $this->gpg->decryptResponse($encryptedData, $keyId, $passphrase);

        print "\n\n";
        echo $decryptedData . PHP_EOL;
        print "\n";
    }
}

$new = new EncryptTestCase();

?>
