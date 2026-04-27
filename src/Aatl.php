<?php

namespace setasign\TrustListFetcher;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use setasign\SetaPDF2\Core\Document;
use setasign\SetaPDF2\Core\Encoding\Encoding;
use setasign\SetaPDF2\Core\FileSpecification;
use setasign\SetaPDF2\Signer\Signer;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Collector;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Exception as ValidationRelatedInfoException;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\Logger;
use setasign\SetaPDF2\Signer\ValidationRelatedInfo\LoggerInterface;
use setasign\SetaPDF2\Signer\X509\Certificate;
use setasign\SetaPDF2\Signer\X509\Collection;

/**
 * Class that loads the AATL and extracts the certificates from it.
 *
 * Related projects and information were gathered from these projects and articles:
 * - https://github.com/PeculiarVentures/tl-create/blob/master/src/formats/aatl.ts
 * - https://kdecherf.com/blog/2024/04/29/validate-aatl-signed-pdf-files-with-pdfsig/
 * - https://github.com/kirei/catt/blob/master/scripts/update-adobe.sh
 * - https://github.com/vargaviktor/aatleutlparser/blob/main/adobetl.sh
 */
class Aatl
{
    protected string $url;
    protected Client $client;
    protected Collection $trustedCertificates;

    protected LoggerInterface $logger;

    public function __construct(
        Client $client,
        Collection $trustedCertificates,
        string $url = 'https://trustlist.adobe.com/tl12.acrobatsecuritysettings'
    ) {
        $this->url = $url;
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
     * @param callable(Certificate $certificate, \DOMElement $identity): void $certificateFound
     * @param callable(\InvalidArgumentException $exception, string $certificate, \DOMElement $identity): void $certificateError
     * @return void
     * @throws Document\ObjectNotFoundException
     * @throws Exception
     * @throws \setasign\SetaPDF2\Core\Exception
     * @throws \setasign\SetaPDF2\Core\Parser\CrossReferenceTable\Exception
     * @throws \setasign\SetaPDF2\Core\Parser\Pdf\InvalidTokenException
     * @throws \setasign\SetaPDF2\Core\Reader\Exception
     * @throws \setasign\SetaPDF2\Core\SecHandler\Exception
     * @throws \setasign\SetaPDF2\Core\Type\Exception
     * @throws \setasign\SetaPDF2\Core\Type\IndirectReference\Exception
     * @throws \setasign\SetaPDF2\Exception
     * @throws \setasign\SetaPDF2\NotImplementedException
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function fetch(callable $certificateFound, callable $certificateError): void
    {
        $logger = $this->getLogger();
        $logger->log('Downloading trust list from: ' . $this->url);

        try {
            $res = $this->client->request('GET', $this->url);
        } catch (GuzzleException $e) {
            $message = 'Unable to process URL: ' . $this->url . ': ' . $e->getMessage();
            $logger->log($message)->decreaseDepth();
            throw new Exception($message, 0, $e);
        }

        $pdf = $res->getBody();

        $document = Document::loadByString($pdf);
        $signatureFieldNames = Signer::getSignatureFieldNames($document);
        if (\count($signatureFieldNames) === 0) {
            throw new Exception('No signature fields found.');
        }

        $logger->log('Validating signature of PDF envelope.');
        $collector = new Collector($this->trustedCertificates);
        foreach ($signatureFieldNames as $signatureFieldName) {
            try {
                $collector->getByFieldName($document, $signatureFieldName);
            } catch (ValidationRelatedInfoException $e) {
                $message = 'Envelope signature could not be validated.';
                $logger->log($message);
                throw new Exception($message, 0, $e);
            }
        }

        $logger->log('Validation successful.');

        // get names
        $names = $document->getCatalog()->getNames();
        $embeddedFiles = $names->getEmbeddedFiles();
        $logger->log('Extracting XML attachment file (SecuritySettings.xml) from PDF envelope.');
        $file = $embeddedFiles->get(Encoding::toPdfString('SecuritySettings.xml'));
        if (!$file instanceof FileSpecification) {
            $message = 'Attachment not found!';
            $logger->log($message);
            throw new Exception($message);
        }
        $xml = $file->getEmbeddedFileStream()->getStream();
        $logger->log(\sprintf('Extracted XML (%s bytes) successful.', strlen($xml)));

        $dom = new \DOMDocument();
        try {
            $logger->log('Load XML into DOMDocument instance.');
            $dom->loadXML($xml);
        } catch (\Throwable $e) {
            $message = 'XML could not be parsed (' . $e->getMessage() . ').';
            $logger->log($message)->decreaseDepth();
            throw new Exception($message, 0, $e);
        }

        $xpath = new \DOMXPath($dom);
        $identities = $xpath->query('//SecuritySettings/TrustedIdentities/Identity');
        $logger->log(\sprintf('Found %d identities in XML.', \count($identities)));

        foreach ($identities as $identity) {
            $this->handleIdentity($identity, $certificateFound, $certificateError);
        }
    }

    /**
     * @param \DOMElement $identity
     * @param callable(Certificate $certificate, \DOMElement $identity): void $certificateFound
     * @param callable(\InvalidArgumentException $exception, string $certificate, \DOMElement $identity): void $certificateError
     * @return void
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    protected function handleIdentity(\DOMElement $identity, callable $certificateFound, callable $certificateError): void
    {
        $logger = $this->getLogger();
        $xpath = new \DOMXPath($identity->ownerDocument);

        $source = $xpath->query('Identification/Source', $identity)->item(0)?->nodeValue;
        if ($source !== 'AATL') {
            $logger->log('Ignoring identify, because its source is not the AATL.');
            return;
        }

        $trustNode = $xpath->query('Trust', $identity)->item(0);
        if (!$trustNode instanceof \DOMElement) {
            $logger->log('Ignoring identify, because Trust node is missing.');
            return;
        }

        // Actually we ignore these information:
//        $trust = [];
//        foreach ($xpath->query('Root|CertifiedDocuments|DynamicContent|JavaScript', $trustNode) as $trustEntry) {
//            /** @var \DOMElement $trustEntry */
//            if ($trustEntry->nodeValue === '1') {
//                $trust[] = $trustEntry->nodeName;
//            }
//        }
//
//        $importAction = (int)$xpath->query('ImportAction', $identity)->item(0)?->nodeValue;

        $certificateString = $xpath->query('Certificate', $identity)->item(0)?->nodeValue;

        try {
            $certificate = new Certificate($certificateString);

            $this->getLogger()->log(\sprintf(
                'Found certificate in trust list: %s (SHA1: %s)',
                $certificate->getSubjectName(),
                $certificate->getDigest()
            ));

            $certificateFound($certificate, $identity);

        } catch (\InvalidArgumentException $e) {
            $this->getLogger()->log('Found certificate but it could not be processed into a Certificate instance!');
            $certificateError($e, $certificateString, $identity);
        }
    }
}
