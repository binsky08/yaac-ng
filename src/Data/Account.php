<?php

namespace binsky\yaac\Data;

use DateTime;

class Account
{
    /**
     * Account constructor.
     * @param DateTime $createdAt
     * @param bool $isValid
     * @param string $accountURL
     */
    public function __construct(
        protected DateTime $createdAt,
        protected bool     $isValid,
        protected string   $accountURL
    )
    {
    }

    /**
     * Return the account ID
     * @return string
     */
    public function getId(): string
    {
        return substr($this->accountURL, strrpos($this->accountURL, '/') + 1);
    }

    /**
     * Return create date for the account
     * @return DateTime
     */
    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }

    /**
     * Return the URL for the account
     * @return string
     */
    public function getAccountURL(): string
    {
        return $this->accountURL;
    }

    /**
     * Returns validation status
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }
}
