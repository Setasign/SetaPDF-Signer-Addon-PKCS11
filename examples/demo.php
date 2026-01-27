<?php

use setasign\SetaPDF\Signer\Module\Pkcs11\Module;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Writer\HttpWriter;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\Signer;

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/../vendor/autoload.php';

$fileToSign = __DIR__ . '/assets/Laboratory-Report.pdf';
$resultPath = 'signed.pdf';

$pin = '123456';

$modulePath = '/usr/lib/softhsm/libsofthsm2.so';
$pkcs11 = new Pkcs11\Module($modulePath);

$slotList = $pkcs11->getSlotList();
$slotId = $slotList[0];

$session = $pkcs11->openSession($slotId, Pkcs11\CKF_RW_SESSION);
$session->login(Pkcs11\CKU_USER, $pin);

$skey = $session->findObjects([
    Pkcs11\CKA_PRIVATE => true,
    Pkcs11\CKA_LABEL => "SetaPDF-Demo"
//    Pkcs11\CKA_LABEL => "SetaPDF-Demo-EC"
])[0];

$module = new Module($skey);
$module->setCertificate(__DIR__ . '/assets/setapdf.pem');
//$module->setCertificate(__DIR__ . '/assets/setapdf-ec-no-pw.pem');
$module->setPssPadding();
$module->setDigest(Digest::SHA_512);

// create a writer instance
$writer = new HttpWriter($resultPath);
// create the document instance
$document = Document::loadByFilename($fileToSign, $writer);

// create the signer instance
$signer = new Signer($document);
$signer->sign($module);

$session->logout();
