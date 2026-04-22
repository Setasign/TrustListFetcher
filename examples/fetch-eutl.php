<?php

use GuzzleHttp\Client;
use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\TrustListFetcher\Eutl;

require_once __DIR__ . '/../vendor/autoload.php';

$url = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';

$trustedCerts = new Collection();
$trustedCerts->add(PemHelper::extractFromFile(__DIR__ . '/../assets/LOTL-signing-certificates-2026-04-15.pem'));

$client = new Client([
    'verify' => __DIR__ . '/../assets/cacert-2026-04-16+interm-for-IE.pem'
]);

$start = microtime(true);

$eutlFetcher = new Eutl($url, $client, $trustedCerts);
$logger = new \setasign\SetaPDF2\Signer\ValidationRelatedInfo\Logger();
$logger->setDirectOutput(true);
$eutlFetcher->setLogger($logger);

$passed = $faulty = 0;
try {
    $eutlFetcher->fetch(
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
