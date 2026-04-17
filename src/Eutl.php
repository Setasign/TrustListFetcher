<?php

namespace Setasign\TrustListFetcher;

use GuzzleHttp\Client;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use Setasign\TrustListFetcher\Xades\Verifier;

class Eutl
{
    protected $lotlUrl;
    protected Client $client;
    protected Collection $trustedCertificates;

    protected $urlsToProcess = [];
    protected $processedUrls = [];

    public function __construct(
        string $lotlUrl,
        Client $client,
        Collection $trustedCertificates
    ) {
        $this->lotlUrl = $lotlUrl;
        $this->client = $client;
        $this->trustedCertificates = $trustedCertificates;
    }

    public function fetch(callable $certificateFound)
    {
        $this->urlsToProcess[] = $this->lotlUrl;

        while (($currentUrl = array_pop($this->urlsToProcess)) !== null) {
            $this->processUrl($currentUrl, $certificateFound);
            $this->processedUrls[] = $currentUrl;
        }
    }

    protected function processUrl($url, callable $certificateFound)
    {
        echo "Processing $url\n";

        $res = $this->client->request('GET', $url);
        if ($res->getStatusCode() !== 200) {
            throw new \Exception('Unable to process URL: ' . $url);
        }

        // TODO: Change to Guzzle/Async to allow processing of lists in parallel

        $xml = $res->getBody();
        $dom = new \DOMDocument();
        $dom->loadXML($xml);

        $verifier = new Verifier();
        $verified = $verifier->verifyDomDocument($dom);
        if ($verified === false) {
            throw new \Exception('Verification failed for: ' . $url);
        }
        echo "verification successful\n";

        /** @var Certificate $signingCertificate */
        [$signingCertificate] = $verified;
        if (!$this->trustedCertificates->contains($signingCertificate)) {
            throw new \Exception(\sprintf(
                'Signing certificate (%s) of %s is not found in the trusted certificates store.',
                $signingCertificate->getSubjectName(),
                $url
            ));
        }

        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('tl', 'http://uri.etsi.org/02231/v2#');
        $xpath->registerNamespace('ns3', 'http://uri.etsi.org/02231/v2/additionaltypes#');

        $pointers = $dom->getElementsByTagName('PointersToOtherTSL')->item(0);
        $pointer = $pointers?->firstElementChild;
        while ($pointer) {
            $tsLocation = $pointer->getElementsByTagName('TSLLocation')->item(0)?->nodeValue;
            $mimeType = $xpath->query('tl:AdditionalInformation/tl:OtherInformation/ns3:MimeType', $pointer)->item(0)?->nodeValue;

            if (
                $tsLocation !== $url
                && $mimeType === 'application/vnd.etsi.tsl+xml'
                && !in_array($tsLocation, $this->processedUrls, true)
            ) {
                $this->urlsToProcess[] = $tsLocation;
            }

            $certificates = $pointer->getElementsByTagName('X509Certificate');
            foreach ($certificates as $certificateNode) {
                $certificate = new Certificate($certificateNode->textContent);
                $this->trustedCertificates->add($certificate);
            }

            $pointer = $pointer->nextElementSibling;
        }

        $tspServices = $xpath->query('//tl:TrustServiceStatusList/tl:TrustServiceProviderList/tl:TrustServiceProvider/tl:TSPServices/tl:TSPService');
        foreach ($tspServices as $tspServiceNode) {
            $serviceInformation = $xpath->query('tl:ServiceInformation', $tspServiceNode)->item(0);
            $x509Certificate = $xpath->query('tl:ServiceDigitalIdentity/tl:DigitalId/tl:X509Certificate', $serviceInformation)->item(0)?->nodeValue;
            if (!$x509Certificate) {
                continue;
            }

            $serviceName = $xpath->query('tl:ServiceName/tl:Name[@xml:lang="en"]', $serviceInformation)->item(0)?->nodeValue;
            $serviceStatus = $xpath->query('tl:ServiceStatus', $serviceInformation)->item(0)?->nodeValue;
            $serviceTypeIdentifier = $xpath->query('tl:ServiceTypeIdentifier', $serviceInformation)->item(0)?->nodeValue;

            try {
                $x509Certificate = strtr($x509Certificate, " \n\r", '');
                $certificate = new Certificate($x509Certificate);

                // TODO: Define what information should be forwarded and put the into an object.
                $certificateFound($certificate, $serviceName, $serviceStatus, $serviceTypeIdentifier);

            } catch (\InvalidArgumentException $e) {
                var_dump($e->getMessage());
                var_dump($x509Certificate);
            }
        }
    }
}
