# SetaPDF-Signer component module for PKCS11

This package offers a module for the [SetaPDF-Signer](https://www.setasign.com/signer)
component that allows you to use keys stored on a PKCS11 compatible device (e.g. HSM,
USB Token) to digital sign PDF documents in pure PHP.

## Requirements

This modules requires the [PKCS11](https://github.com/gamringer/php-pkcs11) PHP
extension to be installed.

You also need to provide the path to the PKCS11 module of your device.

The package is developed and tested on PHP >= 7.4. Requirements of the [SetaPDF-Signer](https://www.setasign.com/signer)
component can be found [here](https://manuals.setasign.com/setapdf-signer-manual/getting-started/#index-1).

## Installation

Add following to your composer.json:

    {
        "require": {
            "setasign/setapdf-signer-addon-pkcs11": "dev-master"
        },
        "repositories": [
            {
                "type": "composer",
                "url": "https://www.setasign.com/downloads/"
            }
        ]
    }

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md) for more details).

## Usage

All classes in this package are located in the namespace `setasign\SetaPDF\Signer\Module\Pkcs11`.

### The `Module` class

This is the main signature module which can be used with the [SetaPDF-Signer](https://www.setasign.com/signer) component.
Internally it holds an own instance of the [PAdES signature module](https://manuals.setasign.com/setapdf-signer-manual/signature-modules/pades/)
and offers all relevant proxy methods.

The only arguments you need to pass to the `Module` instance is a `\Pkcs11\Key` instance of the private
key and the related X509 certificate.

The default padding schema for signatures using RSA keys is RSASSA-PKCS1-v1_5. To use
RSASSA-PSS just call `$module->setPssPadding();`. 

A simple complete signature process would look like this:

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
    ])[0];
    
    $module = new setasign\SetaPDF\Signer\Module\Pkcs11\Module($skey);
    $module->setCertificate('path/to/setapdf.pem');
    $module->setPssPadding();
    $module->setDigest(SetaPDF_Signer_Digest::SHA_512);

    $fileToSign = 'path/to/Laboratory-Report.pdf';

    // create a writer instance
    $writer = new SetaPDF_Core_Writer_Http('signed.pdf');
    // create the document instance
    $document = SetaPDF_Core_Document::loadByFilename($fileToSign, $writer);
    
    // create the signer instance
    $signer = new SetaPDF_Signer($document);
    $signer->sign($module);
    
    $session->logout();


## Testing

For testing purpose we used SoftHSM2 and imported existing test certificates and keys
into it using following command:

    softhsm2-util --import <PATH-TO-CERTIFICATE> --token "<THE-TOKEN-NAME>" --label "<THE-LABEL>" --id <UNIQUE-ID-IN-HEX-NOTATION>

CSR generation and key attestation is not part of this add-on.
