<?php

use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use Setasign\TrustListFetcher\Eutl;

require_once __DIR__ . '/vendor/autoload.php';

$url = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml';
//$url = 'https://eidas.gov.ie/Irelandtslsigned.xml';
//$url = 'https://www.eett.gr/tsl/EL-TSL.xml';
//$url = 'https://tl.bundesnetzagentur.de/TL-DE.XML';

$trustedCerts = new Collection();
$trustedCerts->add(PemHelper::extractFromFile(__DIR__ . '/assets/LOTL-signing-certificates-2026-04-15.pem'));
foreach ($trustedCerts->getAll() as $trustedCert) {
    var_dump($trustedCert->getSubjectName());
}

$client = new \GuzzleHttp\Client([
    'verify' => __DIR__ . '/assets/cacert-2026-04-16+interm-for-IE.pem',
]);

$start = microtime(true);

$eutlFetcher = new Eutl($url, $client, $trustedCerts);

$count = 0;
$eutlFetcher->fetch(function(Certificate $certificate) use (&$count) {
    $count++;
    var_dump($certificate->getSubjectName());
});

var_dump($count);
var_dump(microtime(true) - $start);
