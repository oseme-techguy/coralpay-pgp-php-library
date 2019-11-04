<?php
/**
 * Created by osemeodigie on 14/03/2019
 * Objective: building to scale
*/

require_once 'vendor/autoload.php';

class CoralPayPGPEncryption extends Crypt_GPG
{

    const VERSION = array(0, 3, 0);

    public function __construct(array $options = array()) {
        parent::__construct($options);
    }

    /**
     * Gets the GPG version being used
     * @return $output - the version of the GPG
     */
    public function getVersion() {
        return $this->engine->getVersion();;
    }

    /**
     * Used to encrypt the request message to Cgate.
     * 
     * @return $output - of the encryption
     */
    public function encryptRequest($plainRequest, $keyId) {
        // add the valid public key
        $this->addEncryptKey($keyId);
        $encryptedRequest = $this->encrypt($plainRequest, false); // encrypt the message here

        // remove the message block labels (strip armored header and footer labels)
        //$unArmoredEncryptedMessage = $this->strip_armor($encryptedRequest, 'PGP MESSAGE');
        // convert the binary message to hex
        $encryptedBinMessageToHex = bin2hex($encryptedRequest); 
        return $encryptedBinMessageToHex; // return the hex of the encrypted message
    }


    /**
     * Used to decrypt the response message from Cgate.
     * 
     * @return $output - of the decryption
     */
    public function decryptResponse($encryptedResponse, $keyId, $passphrase) {
        // add the valid private key and passphrase
        $this->addDecryptKey($keyId, $passphrase);
        $hexMessageToBin = hex2bin($encryptedResponse); // convert the hex message to Binary data

        // add the message block labels (convert to armored format)
        $armoredBinMessage = $this->enarmor($hexMessageToBin, 'PGP MESSAGE');
        $decryptedResponse = $this->decrypt($armoredBinMessage, $passphrase);
        return $decryptedResponse; // return the decrypted message
    }


    /**
     * Override the decrypt function in the parent class
     * @return $output - of the encryption (where applicable)
     */
    protected function _decrypt($data, $isFile, $outputFile) {
        $input  = $this->_prepareInput($data, $isFile, false);
        $output = $this->_prepareOutput($outputFile, $input);

        $this->engine->reset();
        $this->engine->setPins($this->decryptKeys);
        $this->engine->setOperation('--decrypt --ignore-mdc-error --skip-verify');
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->run();

        if ($outputFile === null) {
            return $output;
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     * @see http://tools.ietf.org/html/rfc2045
     */
    static function enarmor($data, $marker = 'MESSAGE', array $headers = array()) {
        $text = self::header($marker) . "\n";
        foreach ($headers as $key => $value) {
            $text .= $key . ': ' . (string)$value . "\n";
        }
        $text .= "\n" . wordwrap(base64_encode($data), 76, "\n", true);
        $text .= "\n".'=' . base64_encode(substr(pack('N', self::crc24($data)), 1)) . "\n";
        $text .= self::footer($marker) . "\n";
        return $text;
    }

    /**
     * Strip the message block header 
     * and footer from the message.
     */
    static function strip_armor($data, $marker = 'MESSAGE') {
        // remove the noise from the encrypted data
        $data = str_replace(self::header($marker) . "\n", '' , $data);
        $data = str_replace(self::footer($marker) . "\n", '' , $data);
        $data = trim($data, "\n");
        return $data;
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc2045
     */
    static function unarmor($text, $header = 'PGP PUBLIC KEY BLOCK') {
        $header = self::header($header);
        $text = str_replace(array("\r\n", "\r"), array("\n", ''), $text);
        if (($pos1 = strpos($text, $header)) !== FALSE &&
            ($pos1 = strpos($text, "\n\n", $pos1 += strlen($header))) !== FALSE &&
            ($pos2 = strpos($text, "\n=", $pos1 += 2)) !== FALSE) {
            return base64_decode($text = substr($text, $pos1, $pos2 - $pos1));
        }
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     */
    static function header($marker) {
        return '-----BEGIN ' . strtoupper((string)$marker) . '-----';
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6.2
     */
    static function footer($marker) {
        return '-----END ' . strtoupper((string)$marker) . '-----';
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-6
     * @see http://tools.ietf.org/html/rfc4880#section-6.1
     */
    static function crc24($data) {
        $crc = 0x00b704ce;
        for ($i = 0; $i < strlen($data); $i++) {
            $crc ^= (ord($data[$i]) & 255) << 16;
            for ($j = 0; $j < 8; $j++) {
                $crc <<= 1;
                if ($crc & 0x01000000) {
                    $crc ^= 0x01864cfb;
                }
            }
        }
        return $crc & 0x00ffffff;
    }

    /**
     * @see http://tools.ietf.org/html/rfc4880#section-12.2
     */
    static function bitlength($data) {
        return (strlen($data) - 1) * 8 + (int)floor(log(ord($data[0]), 2)) + 1;
    }

    static function decode_s2k_count($c) {
        return ((int)16 + ($c & 15)) << (($c >> 4) + 6);
    }

    static function encode_s2k_count($iterations) {
        if($iterations >= 65011712) return 255;
        $count = $iterations >> 6;
        $c = 0;
        while($count >= 32) {
            $count = $count >> 1;
            $c++;
        }
        $result = ($c << 4) | ($count - 16);
        if(self::decode_s2k_count($result) < $iterations) {
            return $result + 1;
        }
        return $result;
    }
}