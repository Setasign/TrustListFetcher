<?php

use GuzzleHttp\Client;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\TrustListFetcher\Aatl;

require_once __DIR__ . '/../vendor/autoload.php';

$trustedCerts = new Collection();
$trustedCerts->addFromFile(__DIR__ . '/../assets/Adobe Root CA G2.cer');
$trustedCerts->addFromFile(__DIR__ . '/../assets/DigiCert Trusted Root G4.cer');

$client = new Client();

$start = microtime(true);

$aatlFetcher = new Aatl($client, $trustedCerts);
$aatlFetcher->getLogger()->setDirectOutput(true);

$passed = $faulty = 0;
try {
    $aatlFetcher->fetch(
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
