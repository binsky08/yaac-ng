<?php

namespace binsky\yaac\Data;

use binsky\yaac\Exceptions\CertificateParsingException;
use binsky\yaac\Helper;
use DateTime;

class Certificate
{
    protected string $certificate;
    protected string $intermediateCertificate;
    protected DateTime $expiryDate;

    /**
     * Certificate constructor.
     * @param string $privateKey
     * @param string $csr
     * @param string $chain
     * @throws CertificateParsingException
     */
    public function __construct(
        protected string $privateKey,
        protected string $csr,
        protected string $chain
    )
    {
        list($this->certificate, $this->intermediateCertificate) = Helper::splitCertificate($chain);
        $this->expiryDate = Helper::getCertExpiryDate($chain);
    }

    /**
     * Get the certificate signing request
     * @return string
     */
    public function getCsr(): string
    {
        return $this->csr;
    }

    /**
     * Get the expiry date of the current certificate
     * @return DateTime
     */
    public function getExpiryDate(): DateTime
    {
        return $this->expiryDate;
    }

    /**
     * Return the certificate as a multi-line string. By default, it includes the intermediate certificate as well.
     *
     * @param bool $asChain
     * @return string
     */
    public function getCertificate(bool $asChain = true): string
    {
        return $asChain ? $this->chain : $this->certificate;
    }

    /**
     * Return the intermediate certificate as a multi-line string
     * @return string
     */
    public function getIntermediate(): string
    {
        return $this->intermediateCertificate;
    }

    /**
     * Return the private key as a multi-line string
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
}
