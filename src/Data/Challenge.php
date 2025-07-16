<?php

namespace binsky\yaac\Data;

class Challenge
{
    /**
     * Challenge constructor.
     * @param string $authorizationURL
     * @param string $type
     * @param string $status
     * @param string $url
     * @param string $token
     */
    public function __construct(
        protected string $authorizationURL,
        protected string $type,
        protected string $status,
        protected string $url,
        protected string $token
    )
    {
    }

    /**
     * Get the URL for the challenge
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * Returns challenge type (DNS or HTTP)
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * Returns the token
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Returns the status
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * Returns authorization URL
     * @return string
     */
    public function getAuthorizationURL(): string
    {
        return $this->authorizationURL;
    }
}
