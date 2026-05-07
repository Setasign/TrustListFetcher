<?php

use GuzzleHttp\Client;
use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\TrustListFetcher\Eutl;

require_once __DIR__ . '/../vendor/autoload.php';

$trustedCerts = new Collection();
// Source: https://uri.tsl-switzerland.ch/TrstSvc/TrustedList/schemerules/CH/
$trustedCerts->addFromFile(__DIR__ . '/../assets/CH-TL-cert-B64.cer');

$client = new Client([
    'verify' => __DIR__ . '/../assets/cacert-2026-04-16+interm-for-IE.pem'
]);

$start = microtime(true);

// Switzerland uses the same format as the EU
$chtlFetcher = new Eutl($client, $trustedCerts, 'https://trustedlist.tsl-switzerland.ch/tsl-ch.xml');
$chtlFetcher->getLogger()->setDirectOutput(true);

$passed = $faulty = 0;
try {
    $chtlFetcher->fetch(
        function (Certificate $certificate) use (&$passed) {
            $passed++;
        },

        function (\InvalidArgumentException $e, string $certificate) use (&$faulty) {
            $faulty++;
            var_dump('ERROR', $e->getMessage(), $certificate);
        }
    );

    var_dump($passed, $faulty);
} catch (Exception $e) {
    var_dump($e->getMessage());
}


var_dump(microtime(true) - $start);
