<?php

namespace binsky\yaac\Data;

use binsky\yaac\Client;
use binsky\yaac\Helper;
use DateTime;

class Authorization
{
    protected DateTime $expires;

    /**
     * @var Challenge[]
     */
    protected array $challenges = [];

    /**
     * Authorization constructor.
     * @param string $domain
     * @param string $expires
     * @param string $digest
     * @throws \Exception when DateTime cannot be constructed
     */
    public function __construct(protected string $domain, string $expires, protected string $digest)
    {
        $this->expires = (new DateTime())->setTimestamp(strtotime($expires));
    }

    /**
     * Add a challenge to the authorization
     * @param Challenge $challenge
     */
    public function addChallenge(Challenge $challenge): void
    {
        $this->challenges[] = $challenge;
    }

    /**
     * Return the domain that is being authorized
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }


    /**
     * Return the expiry of the authorization
     * @return DateTime
     */
    public function getExpires(): DateTime
    {
        return $this->expires;
    }

    /**
     * Return array of challenges
     * @return Challenge[]
     */
    public function getChallenges(): array
    {
        return $this->challenges;
    }

    /**
     * Return the HTTP challenge
     * @return Challenge|bool
     */
    public function getHttpChallenge(): Challenge|bool
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_HTTP) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * @return Challenge|bool
     */
    public function getDnsChallenge(): Challenge|bool
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_DNS) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * Return File object for the given challenge
     * @return File|bool
     */
    public function getFile(): File|bool
    {
        $challenge = $this->getHttpChallenge();
        if ($challenge !== false) {
            return new File($challenge->getToken(), $challenge->getToken() . '.' . $this->digest);
        }
        return false;
    }

    /**
     * Returns the DNS record object
     *
     * @return Record|bool
     */
    public function getTxtRecord(): Record|bool
    {
        $challenge = $this->getDnsChallenge();
        if ($challenge !== false) {
            $hash = hash('sha256', $challenge->getToken() . '.' . $this->digest, true);
            $value = Helper::toSafeString($hash);
            return new Record('_acme-challenge.' . $this->getDomain(), $value);
        }

        return false;
    }
}
