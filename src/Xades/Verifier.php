<?php

namespace Setasign\TrustListFetcher\Xades;

use phpseclib3\Crypt\EC\PublicKey as EcPublicKey;
use phpseclib3\File\X509;
use setasign\SetaPDF2\Signer\X509\Certificate;

class Verifier
{
    public function verifyDomDocument(\DomDocument $dom): array|false
    {
        $dsNs = "http://www.w3.org/2000/09/xmldsig#";
        $xadesNs = "http://uri.etsi.org/01903/v1.3.2#";

        $knownAlgorithms = [
            "http://www.w3.org/2001/04/xmlenc#sha256" => 'sha256',
            "http://www.w3.org/2001/04/xmlenc#sha512" => 'sha512',
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => 'sha256',
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => 'sha512',
            'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1' => 'sha256',
            'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1' => 'sha512',
            'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' => 'sha256',
            'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512' => 'sha512',
        ];

        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', $dsNs);
        $xpath->registerNamespace('xades', $xadesNs);

        $signature = $xpath->query('//ds:Signature')->item(0);
        $signedInfo = $xpath->query('ds:SignedInfo', $signature)->item(0);
        if (!$signedInfo instanceof \DOMElement) {
            throw new \Exception('XML does not include a signature.');
        }

        $canonicalizationMethod = $xpath->query('ds:CanonicalizationMethod/@Algorithm', $signedInfo)
            ->item(0)?->nodeValue;
        if ($canonicalizationMethod !== 'http://www.w3.org/2001/10/xml-exc-c14n#') {
            throw new \Exception("CanonicalizationMethod {$canonicalizationMethod} is currently not supported.");
        }

        $references = $xpath->query('ds:Reference', $signedInfo);
        if ($references->count() === 0) {
            throw new \Exception("Cannot find 'Reference' nodes.");
        }

        foreach ($references as $reference) {
            /** @var \DOMElement $reference */
            $target = $reference->attributes->getNamedItem('URI')?->nodeValue;
            $transforms = [];
            foreach ($xpath->query('ds:Transforms/ds:Transform/@Algorithm', $reference) as $transformAlgorithm) {
                $transforms[] = $transformAlgorithm->nodeValue;
            }

            $digestMethod = $xpath->query('ds:DigestMethod/@Algorithm', $reference)->item(0)?->value;
            if (!isset($knownAlgorithms[$digestMethod])) {
                throw new \Exception("Unsupported digest hash method {$digestMethod}!");
            }

            $digestValue = $xpath->query('ds:DigestValue', $reference)->item(0)?->nodeValue;

            // envelope
            if ($target === '') {
                $dom2 = new \DOMDocument();
                $dom2->loadXML($dom->saveXML());
                $digestSubjectNode = $dom2->documentElement;

            } elseif (str_starts_with($target, '#')){
                $targetId = substr($target, 1);
                /** @var \DOMNode $digestSubjectNode */
                $digestSubjectNode = $xpath->query("//*[@Id='$targetId']")->item(0);

            } else {
                throw new \Exception('Unsupported target in Reference node.');
            }

            $digestSubject = null;

            foreach ($transforms as $transform) {
                if ($transform === 'http://www.w3.org/2000/09/xmldsig#enveloped-signature') {
                    $digestSubjectNode->removeChild(
                        // TODO: refactor to $xpath->query()
                        $digestSubjectNode->getElementsByTagNameNS($dsNs, 'Signature')->item(0)
                    );
                    continue;
                }

                if ($transform === 'http://www.w3.org/2001/10/xml-exc-c14n#') {
                    $digestSubject = $digestSubjectNode->C14N(true);
                    continue;
                }

                // not found/tested until now
//                if ($transform === 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments') {
//                    $digestSubject = $digestSubjectNode->C14N(true, true);
//                    continue;
//                }

                throw new \Exception("Unsupported transform algorithm ({$transform}).");
            }

            if ($digestSubject === null) {
                throw new \Exception('No canonicalization transform happened.');
            }

            $calculatedDigest = hash($knownAlgorithms[$digestMethod], $digestSubject, true);
            if (\base64_decode($digestValue) !== $calculatedDigest) {
                throw new \Exception("Invalid digest in Reference with URI '{$target}'!");
            }
        }

        $certContent = trim(
            $xpath->query('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $signature)->item(0)?->textContent
        );

        if (!$certContent) {
            throw new \Exception("Missing 'X509Certificate' node in signature");
        }

        $x509 = new X509();
        $x509->loadX509($certContent);

        $subject = $signedInfo->C14N(true);
        $signatureValue = \base64_decode($xpath->query('ds:SignatureValue', $signature)->item(0)?->textContent);
        $signatureMethod = $xpath->query('ds:SignatureMethod/@Algorithm', $signedInfo)->item(0)?->nodeValue;

        if (!isset($knownAlgorithms[$signatureMethod])) {
            throw new \Exception("Unsupported signature algorithm {$signatureMethod}!!");
        }

        $publicKey = $x509->getPublicKey();
        $publicKey = $publicKey->withHash($knownAlgorithms[$signatureMethod]);
        if (\str_ends_with($signatureMethod, '-rsa-MGF1')) {
            $publicKey = $publicKey->withMGFHash($knownAlgorithms[$signatureMethod]);
        }

        if ($publicKey instanceof EcPublicKey) {
            $publicKey = $publicKey->withSignatureFormat('IEEE');
        }

        if (!$publicKey->verify($subject, $signatureValue)) {
            return false;
        }

        // TODO: refactor to $xpath->query()
        $signTime = $dom->getElementsByTagNameNS($xadesNs, 'SigningTime')->item(0)->nodeValue;
        return [
            new Certificate($certContent),
            \DateTimeImmutable::createFromFormat('Y-m-d\TH:i:sp', $signTime)
        ];
    }
}
