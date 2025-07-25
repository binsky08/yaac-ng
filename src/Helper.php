<?php

namespace binsky\yaac;

use binsky\yaac\Exceptions\CertificateParsingException;
use binsky\yaac\Exceptions\CertificateSigningRequestException;
use binsky\yaac\Exceptions\OpensslKeyParsingException;
use DateTime;
use OpenSSLAsymmetricKey;

/**
 * Class Helper
 * This class contains helper methods for certificate handling
 * @package Afosto\Acme
 */
class Helper
{
    /**
     * Formatter
     * @param $pem
     * @return false|string
     * @see https://eidson.info/post/php_eol_is_broken
     */
    public static function toDer($pem): false|string
    {
        $lines = preg_split('/\n|\r\n?/', $pem);
        $lines = array_slice($lines, 1, -1);

        return base64_decode(implode('', $lines));
    }

    /**
     * Return certificate expiry date
     *
     * @param $certificate
     *
     * @return DateTime
     * @throws CertificateParsingException
     */
    public static function getCertExpiryDate($certificate): DateTime
    {
        $info = openssl_x509_parse($certificate);
        if ($info === false) {
            throw new CertificateParsingException('Could not parse certificate');
        }
        $dateTime = new DateTime();
        $dateTime->setTimestamp($info['validTo_time_t']);

        return $dateTime;
    }

    /**
     * Get a new key
     *
     * @param int $keyLength
     * @return string
     */
    public static function getNewKey(int $keyLength): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => $keyLength,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    /**
     * Get a new CSR
     *
     * @param array $domains
     * @param       $key
     *
     * @return string
     * @throws CertificateSigningRequestException
     */
    public static function getCsr(array $domains, $key): string
    {
        $primaryDomain = current(($domains));
        $config = [
            '[req]',
            'distinguished_name=req_distinguished_name',
            '[req_distinguished_name]',
            '[v3_req]',
            '[v3_ca]',
            '[SAN]',
            'subjectAltName=' . implode(',', array_map(function ($domain) {
                return 'DNS:' . $domain;
            }, $domains)),
        ];

        $fn = tempnam(sys_get_temp_dir(), md5(microtime(true)));
        file_put_contents($fn, implode("\n", $config));
        $csr = openssl_csr_new([
            'countryName' => 'NL',
            'commonName' => $primaryDomain,
        ], $key, [
            'config' => $fn,
            'req_extensions' => 'SAN',
            'digest_alg' => 'sha512',
        ]);
        unlink($fn);

        if ($csr === false) {
            throw new CertificateSigningRequestException('Could not create a CSR');
        }

        if (!openssl_csr_export($csr, $result)) {
            throw new CertificateSigningRequestException('CRS export failed');
        }

        return trim($result);
    }

    /**
     * Make a safe base64 string
     *
     * @param $data
     *
     * @return string
     */
    public static function toSafeString($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Get the key information
     *
     * @param OpenSSLAsymmetricKey $key
     * @return array ["bits" => "int", "key" => "string", "rsa" => "array", "dsa" => "array", "dh" => "array", "ec" => "array", "type" => "int"]
     * @throws OpensslKeyParsingException
     */
    public static function getKeyDetails(OpenSSLAsymmetricKey $key): array
    {
        $accountDetails = openssl_pkey_get_details($key);
        if ($accountDetails === false) {
            throw new OpensslKeyParsingException('Could not load account details');
        }

        return $accountDetails;
    }

    /**
     * Split a two certificate bundle into separate multi-line string certificates
     * @param string $chain
     * @return string[] [$domain, $intermediate]
     * @throws CertificateParsingException
     */
    public static function splitCertificate(string $chain): array
    {
        preg_match(
            '/^(?<domain>-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)\n'
            . '(?<intermediate>-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)$/s',
            $chain,
            $certificates
        );

        $domain = $certificates['domain'] ?? null;
        $intermediate = $certificates['intermediate'] ?? null;

        if (!$domain || !$intermediate) {
            throw new CertificateParsingException('Could not parse certificate string');
        }

        return [$domain, $intermediate];
    }
}
