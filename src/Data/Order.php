<?php


namespace binsky\yaac\Data;

use DateTime;

class Order
{
    protected DateTime $expiresAt;

    /**
     * Order constructor.
     * @param array $domains
     * @param string $url
     * @param string $status
     * @param string $expiresAt
     * @param array $identifiers
     * @param array $authorizations
     * @param string $finalizeURL
     * @param string $certificate for asynchronous order support
     * @throws \Exception when DateTime cannot be constructed
     */
    public function __construct(
        protected array  $domains,
        protected string $url,
        protected string $status,
        string           $expiresAt,
        protected array  $identifiers,
        protected array  $authorizations,
        protected string $finalizeURL,
        protected string $certificate = '',
    )
    {
        //Handle the microtime date format
        if (str_contains($expiresAt, '.')) {
            $expiresAt = substr($expiresAt, 0, strpos($expiresAt, '.')) . 'Z';
        }
        $this->expiresAt = (new DateTime())->setTimestamp(strtotime($expiresAt));
    }

    /**
     * Returns the order number
     * @return string
     */
    public function getId(): string
    {
        return substr($this->url, strrpos($this->url, '/') + 1);
    }

    /**
     * Returns the order URL
     * @return string
     */
    public function getURL(): string
    {
        return $this->url;
    }

    /**
     * Return set of authorizations for the order
     * @return string[]
     */
    public function getAuthorizationURLs(): array
    {
        return $this->authorizations;
    }

    /**
     * Returns order status
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Returns expires at
     * @return DateTime
     */
    public function getExpiresAt(): DateTime
    {
        return $this->expiresAt;
    }

    /**
     * Returns domains as identifiers
     * @return array
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * Returns url
     * @return string
     */
    public function getFinalizeURL(): string
    {
        return $this->finalizeURL;
    }

    /**
     * Returns certificate
     * @return string
     */
    public function getCertificate(): string
    {
        return $this->certificate;
    }

    /**
     * Returns domains for the order
     * @return array
     */
    public function getDomains(): array
    {
        return $this->domains;
    }
}
