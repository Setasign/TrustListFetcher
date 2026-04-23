# TrustListFetcher (WIP)
A PHP package licensed under the [MIT](LICENSE) that allows you to download or extract all certificates
from trust lists such as the [EUTL](https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls) or AATL.

## Installation

You can install the package with [Composer](https://getcomposer.org/):

```bash
composer require setasign/trust-list-fetcher
```

The package makes use of classes of the [SetaPDF-Signer](https://www.setasign.com/products/setapdf-signer/) component.
A valid license and the correct composer repository has to be setup in your composer.json, too.

The root namespace for all classes is `setasign/TrustListFetcher`.

## HTTP requests
All internal HTTP requests are done by a `Client` instance of [`Guzzle`](https://docs.guzzlephp.org/en/stable/)
which has to be injected in the constructor method of the respective trust list class.

```php
$client = new GuzzleHttp\Client([
    'verify' => __DIR__ . '/../assets/cacert-2026-04-16+interm-for-IE.pem'
]);
```

## Certificates from the EUTL

The `Eutl` class allows you to download all certificates from the [EUTL](https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/EU).

Based on the [Official Journal of the European Union (OJEU) on 14 April 2026](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=OJ:C_202601944) the class
starts to load the "List Of Trust Lists" (LOTL) from https://ec.europa.eu/tools/lotl/eu-lotl.xml and recursively accesses
the individual trust lists by the member states.

During this process the integrity and trust of the individual trust list signing certificates are verified.
The process has to start with a collection of trusted certificates extracted from the mentioned [OJEU](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=OJ:C_202601944)
which are stored in the file [LOTL-signing-certificates-2026-04-15.pem](assets/LOTL-signing-certificates-2026-04-15.pem).

```php
//...
use setasign\SetaPDF2\Signer\PemHelper;
use setasign\SetaPDF2\Signer\X509\Collection;
//...

$trustedCerts = new Collection();
$trustedCerts->add(
    PemHelper::extractFromFile(__DIR__ . '/../assets/LOTL-signing-certificates-2026-04-15.pem')
);
```

Then you can simply initiate an instance:

```php
//...
use setasign\TrustListFetcher\Eutl;
//...

$eutlFetcher = new Eutl($client, $trustedCerts);
```
The real process starts by calling the `fetch()` method, which accepts two callbacks:
`$certificateFound` which is executed if a certificate is found and `$certificateError`
which is executed if a certificate cannot be interpreted by the `Certificate` instance:

```php
//...
use setasign\SetaPDF2\Signer\X509\Certificate;
//...

$eutlFetcher->fetch(
    function (Certificate $certificate) {
        // a certificate was successfully extract
    },
    function (\InvalidArgumentException $e, string $certificate) {
        // the resolved certificate could not be converted to a Certificate instance 
    }
);
```

If it is not possible to process all trust lists, the method will throw an
`Exception` and the resolved certificates should be seen as incomplete.

NOTE: The whole process can take several seconds or minutes depending on the response 
times of the individual trust list endpoints.

### Error Handling and Logging
Only if the `fetch()` call is executed without any thrown exception, the process 
can be seen as complete.

To understand what's happening in the whole process the `Eutl` instance allows you access to a default [`Logger`](https://manuals.setasign.com/api-reference/setapdf/c/setasign.SetaPDF2.Signer.ValidationRelatedInfo.Logger)
instance by its `getLogger()` method.

You can enable direct output of the logger instance this way:

```php
$eutlFetcher->getLogger()->setDirectOutput(true);
```

All logs will be echoed out directly.

If you only want to access the log in case of an exception, just access it in a catch-block:

```php
try {
    $eutlFetcher->fetch(
        function (Certificate $certificate) {
            // ...
        },
        function (\InvalidArgumentException $e, string $certificate) {
            // ... 
        }
    );
   
    // commit all resolved certificates
    
} catch (\Throwable $e) {
    // revert or simply not process all resolved certificates
    
    echo 'Error: ' . $e->getMessage() . PHP_EOL;
    foreach ($eutlFetcher->getLogger()->getLogs() as $logEntry) {
        echo \str_repeat(' ', $log->getDepth() * 4) . $log->getMessage() . PHP_EOL;
    }
}
```

## Certificates from the AATL

TODO: Actually there's no `Aatl` fetcher class implemented.