<?php

namespace setasign\TrustListFetcher;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Logger;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\LoggerInterface;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;
use setasign\TrustListFetcher\Xades\Verifier;

class Eutl
{
    protected string $lotlUrl;
    protected Client $client;
    protected Collection $trustedCertificates;

    protected array $urlsToProcess = [];
    protected array $processedUrls = [];

    protected LoggerInterface $logger;

    public function __construct(
        string $lotlUrl,
        Client $client,
        Collection $trustedCertificates
    ) {
        $this->lotlUrl = $lotlUrl;
        $this->client = $client;
        $this->trustedCertificates = $trustedCertificates;
    }

    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function getLogger(): LoggerInterface
    {
        if (!isset($this->logger)) {
            $this->logger = new Logger();
        }

        return $this->logger;
    }

    /**
     * @param callable(Certificate $certificate, \DOMElement $x509CertificateNode): void $certificateFound
     * @param callable(\InvalidArgumentException $exception, string $certificate, \DOMElement $x509CertificateNode): void $certificateError
     * @return void
     * @throws Exception
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     */
    public function fetch(callable $certificateFound, callable $certificateError)
    {
        $this->urlsToProcess[] = $this->lotlUrl;

        while (($currentUrl = array_pop($this->urlsToProcess)) !== null) {
            $this->processUrl($currentUrl, $certificateFound, $certificateError);
            $this->processedUrls[] = $currentUrl;
        }
    }

    /**
     * @param string $url
     * @param callable(Certificate $certificate, \DOMElement $x509CertificateNode): void $certificateFound
     * @param callable(\InvalidArgumentException $exception, string $certificate, \DOMElement $x509CertificateNode): void $certificateError
     * @return void
     * @throws Exception
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     */
    protected function processUrl(string $url, callable $certificateFound, callable $certificateError): void
    {
        $logger = $this->getLogger();
        $logger->log('Processing trust list at: ' . $url)
            ->increaseDepth();

        try {
            $res = $this->client->request('GET', $url);
        } catch (GuzzleException $e) {
            $message = 'Unable to process URL: ' . $url . ': ' . $e->getMessage();
            $logger->log($message)->decreaseDepth();
            throw new Exception($message, 0, $e);
        }

        // TODO: Change to Guzzle/Async to allow processing of lists in parallel

        $xml = $res->getBody();
        $dom = new \DOMDocument();
        try {
            $dom->loadXML($xml);
        } catch (\Throwable $e) {
            $message = 'Returned XML could not be parsed (' . $e->getMessage() . ').';
            $logger->log($message)->decreaseDepth();
            throw new Exception($message, 0, $e);
        }

        try {
            $verified = (new Verifier())->verifyDomDocument($dom);
        } catch (\Throwable $e) {
            $message = 'XADES signature verification failed for trust list at ' . $url;
            $logger->log($message)->decreaseDepth();
            throw new Exception($message, 0, $e);
        }

        $logger->log('XADES signature verification successfully.');

        /** @var Certificate $signingCertificate */
        [$signingCertificate] = $verified;
        $this->getLogger()->log('Signing certificate is: '. $signingCertificate->getSubjectName());
        if (!$this->trustedCertificates->contains($signingCertificate)) {
            $message = \sprintf(
                'Signing certificate (%s) of %s is not found in the trusted certificates store.',
                $signingCertificate->getSubjectName(),
                $url
            );
            $logger->log($message)->decreaseDepth();
            throw new Exception($message);
        }

        $logger->log('Signing certificate is found in the trusted certificates store.');

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
                $logger->log('Found pointer to another trust list at: ' . $tsLocation . ' (stored for further processing)');
                $this->urlsToProcess[] = $tsLocation;
            }

            $certificates = $pointer->getElementsByTagName('X509Certificate');
            if ($certificates->length > 0) {
                $logger
                    ->log(\sprintf('Found %d signing certificates for referenced trust lists.', $certificates->length))
                    ->increaseDepth();
            }
            foreach ($certificates as $certificateNode) {
                $certificate = new Certificate($certificateNode->textContent);
                $this->trustedCertificates->add($certificate);
                $logger->log(\sprintf(
                    'Added certificate to trusted certificates store: %s (SHA1: %s)',
                    $certificate->getSubjectName(),
                    $certificate->getDigest()
                ));
            }

            if ($certificates->length > 0) {
                $logger->decreaseDepth();
            }

            $pointer = $pointer->nextElementSibling;
        }

        $tspServices = $xpath->query(
            '//tl:TrustServiceStatusList/tl:TrustServiceProviderList/tl:TrustServiceProvider/tl:TSPServices/tl:TSPService'
        );
        foreach ($tspServices as $tspServiceNode) {
            $this->handleTspServiceNode($tspServiceNode, $certificateFound, $certificateError);
        }

        $this->getLogger()->decreaseDepth();
    }

    /**
     * @param \DOMElement $tspServiceNode
     * @param callable(Certificate $certificate, \DOMElement $x509CertificateNode): void $certificateFound
     * @param callable(\InvalidArgumentException $exception, string $certificate, \DOMElement $x509CertificateNode): void $certificateError
     * @return void
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     */
    protected function handleTspServiceNode(
        \DOMElement $tspServiceNode,
        callable $certificateFound,
        callable $certificateError
    ): void {
        $xpath = new \DOMXPath($tspServiceNode->ownerDocument);
        $xpath->registerNamespace('tl', 'http://uri.etsi.org/02231/v2#');

        $x509Certificates = $xpath->query(
            'tl:ServiceInformation/tl:ServiceDigitalIdentity/tl:DigitalId/tl:X509Certificate',
            $tspServiceNode
        );

        foreach ($x509Certificates as $x509Certificate) {
            try {
                $certificate = new Certificate($x509Certificate->nodeValue);

                $this->getLogger()->log(\sprintf(
                    'Found certificate in trust list: %s (SHA1: %s)',
                    $certificate->getSubjectName(),
                    $certificate->getDigest()
                ));

                $certificateFound($certificate, $x509Certificate);

            } catch (\InvalidArgumentException $e) {
                $this->getLogger()->log('Found certificate but it could not be processed into a Certificate instance!');
                $certificateError($e, $x509Certificate->nodeValue, $x509Certificate);
            }
        }
    }
}
