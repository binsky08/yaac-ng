<?php

namespace binsky\yaac\Data;

class Record
{
    /**
     * Record constructor.
     * @param string $name
     * @param string $value
     */
    public function __construct(protected string $name, protected string $value)
    {
    }

    /**
     * Return the DNS TXT record name for validation
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Return the record value for DNS validation
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }
}
