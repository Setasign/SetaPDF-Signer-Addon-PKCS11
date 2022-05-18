<?php

/**
 * @copyright Copyright (c) 2022 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

declare(strict_types=1);

namespace setasign\SetaPDF\Signer\Module\Pkcs11;

use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Asn1_Oid as Asn1Oid;
use SetaPDF_Signer_Digest as Digest;

class Module implements
    \SetaPDF_Signer_Signature_Module_ModuleInterface,
    \SetaPDF_Signer_Signature_DictionaryInterface,
    \SetaPDF_Signer_Signature_DocumentInterface
{
    protected \SetaPDF_Signer_Signature_Module_Pades $padesModule;

    protected \Pkcs11\Key $privateKey;

    protected int $keyType;

    protected bool $pssPadding = false;

    /**
     * @param \Pkcs11\Key|null $privateKey
     */
    public function __construct(\Pkcs11\Key $privateKey = null)
    {
        $this->padesModule = new \SetaPDF_Signer_Signature_Module_Pades();

        if ($privateKey !== null) {
            $this->setPrivateKey($privateKey);
        }
    }

    /**
     * @param \Pkcs11\Key $privateKey
     * @return void
     */
    public function setPrivateKey(\Pkcs11\Key $privateKey): void
    {
        $attributes = $privateKey->getAttributeValue([
            \Pkcs11\CKA_PRIVATE,
            \Pkcs11\CKA_SIGN,
            \Pkcs11\CKA_KEY_TYPE
        ]);

        // note: before php-pkcs11 v1.1 the attribute types were always strings
        if (!is_bool($attributes[\Pkcs11\CKA_PRIVATE])) {
            $attributes[\Pkcs11\CKA_PRIVATE] = $attributes[\Pkcs11\CKA_PRIVATE] === "\x01";
        }
        if (!is_bool($attributes[\Pkcs11\CKA_SIGN])) {
            $attributes[\Pkcs11\CKA_SIGN] = $attributes[\Pkcs11\CKA_SIGN] === "\x01";
        }
        if (!is_int($attributes[\Pkcs11\CKA_KEY_TYPE])) {
            $attributes[\Pkcs11\CKA_KEY_TYPE] = \current(\unpack('P', $attributes[\Pkcs11\CKA_KEY_TYPE]));
        }
        
        if (!$attributes[\Pkcs11\CKA_PRIVATE]) {
            throw new \InvalidArgumentException('The passed key is not a private key.');
        }

        if (!$attributes[\Pkcs11\CKA_SIGN]) {
            throw new \InvalidArgumentException('Signing is not allowed with this key.');
        }

        $this->keyType = $attributes[\Pkcs11\CKA_KEY_TYPE];

        switch ($this->keyType) {
            case \Pkcs11\CKK_RSA:
            case \Pkcs11\CKK_EC:
                break;
            default:
                throw new \InvalidArgumentException('Only RSA and EC keys are supported.');
        }

        $this->privateKey = $privateKey;
    }

    /**
     * Set the signing certificate.
     *
     * @param string|\SetaPDF_Signer_X509_Certificate $certificate PEM encoded certificate, path to the PEM encoded
     *                                                            certificate or a certificate instance.
     * @throws \InvalidArgumentException
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setCertificate($certificate): void
    {
        $this->padesModule->setCertificate($certificate);
    }

    /**
     * Get the certificate value.
     *
     * @return string|\SetaPDF_Signer_X509_Certificate
     */
    public function getCertificate()
    {
        return $this->padesModule->getCertificate();
    }

    /**
     * Set the digest algorithm to use when signing.
     *
     * @param string $digest Allowed values are sha256, sha386, sha512
     * @see \SetaPDF_Signer_Signature_Module_Pades::setDigest()
     */
    public function setDigest(string $digest): void
    {
        $this->padesModule->setDigest($digest);
    }

    /**
     * Get the digest algorithm.
     *
     * @return string
     */
    public function getDigest(): string
    {
        return $this->padesModule->getDigest();
    }

    /**
     * Add additional certificates which are placed into the CMS structure.
     *
     * @param array|\SetaPDF_Signer_X509_Collection $extraCertificates PEM encoded certificates or pathes to PEM encoded
     *                                                                 certificates.
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function setExtraCertificates($extraCertificates): void
    {
        $this->padesModule->setExtraCertificates($extraCertificates);
    }

    /**
     * Adds an OCSP response which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_Ocsp_Response $ocspResponse DER encoded OCSP response or OCSP response instance.
     * @throws \SetaPDF_Signer_Exception
     */
    public function addOcspResponse($ocspResponse): void
    {
        $this->padesModule->addOcspResponse($ocspResponse);
    }

    /**
     * Adds an CRL which will be embedded in the CMS structure.
     *
     * @param string|\SetaPDF_Signer_X509_Crl $crl
     */
    public function addCrl($crl): void
    {
        $this->padesModule->addCrl($crl);
    }

    /**
     * @inheritDoc
     * @throws \SetaPDF_Signer_Exception
     */
    public function updateSignatureDictionary(\SetaPDF_Core_Type_Dictionary $dictionary): void
    {
        $this->padesModule->updateSignatureDictionary($dictionary);
    }

    /**
     * @inheritDoc
     */
    public function updateDocument(\SetaPDF_Core_Document $document): void
    {
        $this->padesModule->updateDocument($document);
    }

    /**
     * Get the complete Cryptographic Message Syntax structure.
     *
     * @return Asn1Element
     * @throws \SetaPDF_Signer_Exception
     */
    public function getCms(): Asn1Element
    {
        return $this->padesModule->getCms();
    }

    /**
     * Define whether to use PSS or PKCSV1_5 padding with RSA keys.
     *
     * @param bool $pssPadding
     * @return void
     */
    public function setPssPadding(bool $pssPadding = true): void
    {
        if ($pssPadding && $this->keyType !== \Pkcs11\CKK_RSA) {
            throw new \InvalidArgumentException('The key is not a RSA key and does not support PSS padding.');
        }
        $this->pssPadding = $pssPadding;
    }

    /**
     * Get whether PSS or PKCSV1_5 padding is used with RSA keys.
     *
     * @return bool
     */
    public function getPssPadding(): bool
    {
        return $this->pssPadding;
    }

    /**
     * @param \SetaPDF_Core_Reader_FilePath $tmpPath
     * @return string
     * @throws \SetaPDF_Signer_Exception
     */
    public function createSignature(\SetaPDF_Core_Reader_FilePath $tmpPath): string
    {
        $hashData = $this->padesModule->getDataToSign($tmpPath);
        $digest = $this->padesModule->getDigest();

        if ($this->keyType === \Pkcs11\CKK_RSA) {
            if ($this->getPssPadding()) {
                switch ($digest) {
                    case Digest::SHA_256:
                        $saltLength = 256 / 8;
                        $pssParams = new \Pkcs11\RsaPssParams(\Pkcs11\CKM_SHA256, \Pkcs11\CKG_MGF1_SHA256, $saltLength);
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA256_RSA_PKCS_PSS, $pssParams);
                        break;
                    case Digest::SHA_384:
                        $saltLength = 384 / 8;
                        $pssParams = new \Pkcs11\RsaPssParams(\Pkcs11\CKM_SHA384, \Pkcs11\CKG_MGF1_SHA384, $saltLength);
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA384_RSA_PKCS_PSS, $pssParams);
                        break;
                    case Digest::SHA_512:
                        $saltLength = 512/ 8;
                        $pssParams = new \Pkcs11\RsaPssParams(\Pkcs11\CKM_SHA512, \Pkcs11\CKG_MGF1_SHA512, $saltLength);
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA512_RSA_PKCS_PSS, $pssParams);
                        break;
                    default:
                        throw new Exception('Unsupported signature digest algorithm.');
                }

                /** @var Asn1Element $cms */
                $cms = $this->padesModule->getCms();

                $signatureAlgorithmIdentifier = Asn1Element::findByPath('1/0/4/0/4', $cms);
                $signatureAlgorithmIdentifier->getChild(0)->setValue(
                    Asn1Oid::encode("1.2.840.113549.1.1.10")
                );
                $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(1));
                $signatureAlgorithmIdentifier->addChild(new Asn1Element(
                    Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                    '',
                    [
                        new Asn1Element(
                            Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
                            '',
                            [
                                new Asn1Element(
                                    Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                    '',
                                    [
                                        new Asn1Element(
                                            Asn1Element::OBJECT_IDENTIFIER,
                                            Asn1Oid::encode(Digest::getOid($digest))
                                        ),
                                        new Asn1Element(Asn1Element::NULL)
                                    ]
                                )
                            ]
                        ),
                        new Asn1Element(
                            Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
                            '',
                            [
                                new Asn1Element(
                                    Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                    '',
                                    [
                                        new Asn1Element(
                                            Asn1Element::OBJECT_IDENTIFIER,
                                            Asn1Oid::encode('1.2.840.113549.1.1.8')
                                        ),
                                        new Asn1Element(
                                            Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                            '',
                                            [
                                                new Asn1Element(
                                                    Asn1Element::OBJECT_IDENTIFIER,
                                                    Asn1Oid::encode(Digest::getOid($digest))
                                                ),
                                                new Asn1Element(Asn1Element::NULL)
                                            ]
                                        )
                                    ]
                                )
                            ]
                        ),
                        new Asn1Element(
                            Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02",
                            '',
                            [
                                new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                            ]
                        )
                    ]
                ));

            } else {
                // PKCSV1_5 padding
                switch ($digest) {
                    case Digest::SHA_256:
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA256_RSA_PKCS);
                        break;
                    case Digest::SHA_384:
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA384_RSA_PKCS);
                        break;
                    case Digest::SHA_512:
                        $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA512_RSA_PKCS);
                        break;
                    default:
                        throw new Exception('Unsupported signature digest algorithm.');
                }
            }

        } elseif ($this->keyType === \Pkcs11\CKK_EC) {
            $hashData = \hash($digest, $hashData, true);
            $mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_ECDSA);
        } else {
            throw new Exception('Unsupported key type.');
        }

        $signatureValue = $this->privateKey->sign($mechanism, $hashData);

        if ($this->keyType === \Pkcs11\CKK_EC) {
            $len = \strlen($signatureValue);

            $s = \substr($signatureValue, 0, $len / 2);
            if (\ord($s[0]) & 0x80) { // ensure positive integers
                $s = "\0" . $s;
            }
            $r = \substr($signatureValue, $len / 2);
            if (\ord($r[0]) & 0x80) { // ensure positive integers
                $r = "\0" . $r;
            }

            $signatureValue = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(Asn1Element::INTEGER, $s),
                    new Asn1Element(Asn1Element::INTEGER, $r),
                ]
            );
        }

        $this->padesModule->setSignatureValue($signatureValue);

        return (string) $this->getCms();
    }
}
