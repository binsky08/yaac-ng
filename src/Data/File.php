<?php

namespace binsky\yaac\Data;

class File
{
    /**
     * File constructor.
     * @param string $filename
     * @param string $contents
     */
    public function __construct(protected string $filename, protected string $contents)
    {
    }

    /**
     * Return the filename for HTTP validation
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * Return the file contents for HTTP validation
     * @return string
     */
    public function getContents(): string
    {
        return $this->contents;
    }
}
