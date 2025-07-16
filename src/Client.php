<?php

namespace binsky\yaac;

use binsky\yaac\Data\Account;
use binsky\yaac\Data\Authorization;
use binsky\yaac\Data\Certificate;
use binsky\yaac\Data\Challenge;
use binsky\yaac\Data\Order;
use binsky\yaac\Exceptions\CertificateParsingException;
use binsky\yaac\Exceptions\CertificateSigningRequestException;
use binsky\yaac\Exceptions\GenericYaacException;
use binsky\yaac\Exceptions\OpensslKeyParsingException;
use binsky\yaac\Exceptions\OpensslSignatureGenerationException;
use DateTime;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Utils;
use League\Flysystem\Filesystem;
use League\Flysystem\FilesystemException;
use LogicException;
use OpenSSLAsymmetricKey;
use Psr\Http\Message\ResponseInterface;

class Client
{
    /**
     * Live url
     */
    const DIRECTORY_LIVE = 'https://acme-v02.api.letsencrypt.org/directory';

    /**
     * Staging url
     */
    const DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    /**
     * Flag for production
     */
    const MODE_LIVE = 'live';

    /**
     * Flag for staging
     */
    const MODE_STAGING = 'staging';

    /**
     * New account directory
     */
    const DIRECTORY_NEW_ACCOUNT = 'newAccount';

    /**
     * Nonce directory
     */
    const DIRECTORY_NEW_NONCE = 'newNonce';

    /**
     * Order certificate directory
     */
    const DIRECTORY_NEW_ORDER = 'newOrder';

    /**
     * Http validation
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * DNS validation
     */
    const VALIDATION_DNS = 'dns-01';

    protected string $nonce;
    protected Account $account;
    protected array $privateKeyDetails;
    protected string $accountKey;
    protected Filesystem $filesystem;
    protected array $directories = [];
    protected array $header = [];
    protected string $digest;
    protected HttpClient $httpClient;

    /**
     * Client constructor.
     *
     * @param array $config
     *
     * @type string $mode The mode for ACME (production / staging)
     * @type Filesystem $fs Filesystem for storage of static data
     * @type string $basePath The base path for the filesystem (used to store account information and csr / keys
     * @type string $username The acme username
     * @type string $source_ip The source IP for Guzzle (via curl.options) to bind to (defaults to 0.0.0.0 [OS default])
     *
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     * @throws LogicException
     */
    public function __construct(protected array $config = [])
    {
        if ($this->getOption('fs', false)) {
            $this->filesystem = $this->getOption('fs');
        } else {
            throw new LogicException('No filesystem option supplied');
        }

        if ($this->getOption('username', false) === false) {
            throw new LogicException('Username not provided');
        }

        $this->init();
    }

    /**
     * Get an existing order by ID
     *
     * @param $id
     * @return Order
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     * @throws \Exception when DateTime cannot be constructed in \binsky\yaac\Data\Order::__construct
     */
    public function getOrder($id): Order
    {
        $url = str_replace('new-order', 'order', $this->getUrl(self::DIRECTORY_NEW_ORDER));
        $url = $url . '/' . $this->getAccount()->getId() . '/' . $id;
        $response = $this->request($url, $this->signPayloadKid(null, $url));
        $data = json_decode((string)$response->getBody(), true);

        $domains = [];
        foreach ($data['identifiers'] as $identifier) {
            $domains[] = $identifier['value'];
        }

        // certificate provided here only by asynchronous order finalization
        $certificate = (!empty($data['certificate'])) ? $data['certificate'] : '';

        return new Order(
            $domains,
            $url,
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize'],
            $certificate,
        );
    }

    /**
     * Get ready status for order
     *
     * @param Order $order
     * @return bool
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    public function isReady(Order $order): bool
    {
        $order = $this->getOrder($order->getId());
        return $order->getStatus() == 'ready';
    }


    /**
     * Create a new order
     *
     * @param array $domains
     * @return Order
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     * @throws \Exception when DateTime cannot be constructed in \binsky\yaac\Data\Order::__construct
     */
    public function createOrder(array $domains): Order
    {
        $identifiers = [];
        foreach ($domains as $domain) {
            $identifiers[] =
                [
                    'type' => 'dns',
                    'value' => $domain,
                ];
        }

        $url = $this->getUrl(self::DIRECTORY_NEW_ORDER);
        $response = $this->request($url, $this->signPayloadKid(
            [
                'identifiers' => $identifiers,
            ],
            $url
        ));

        $data = json_decode((string)$response->getBody(), true);

        return new Order(
            $domains,
            $response->getHeaderLine('location'),
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize']
        );
    }

    /**
     * Obtain authorizations
     *
     * @param Order $order
     * @return array|Authorization[]
     * @throws FilesystemException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     * @throws \Exception when DateTime cannot be constructed in \binsky\yaac\Data\Authorization::__construct
     */
    public function authorize(Order $order): array
    {
        $authorizations = [];
        foreach ($order->getAuthorizationURLs() as $authorizationURL) {
            $response = $this->request(
                $authorizationURL,
                $this->signPayloadKid(null, $authorizationURL)
            );
            $data = json_decode((string)$response->getBody(), true);
            $authorization = new Authorization($data['identifier']['value'], $data['expires'], $this->getDigest());

            foreach ($data['challenges'] as $challengeData) {
                $challenge = new Challenge(
                    $authorizationURL,
                    $challengeData['type'],
                    $challengeData['status'],
                    $challengeData['url'],
                    $challengeData['token']
                );
                $authorization->addChallenge($challenge);
            }
            $authorizations[] = $authorization;
        }

        return $authorizations;
    }

    /**
     * Run a self-test for the authorization
     * @param Authorization $authorization
     * @param string $type
     * @param int $maxAttempts
     * @return bool
     * @throws GuzzleException
     */
    public function selfTest(Authorization $authorization, string $type = self::VALIDATION_HTTP, int $maxAttempts = 15): bool
    {
        if ($type == self::VALIDATION_HTTP) {
            return $this->selfHttpTest($authorization, $maxAttempts);
        } elseif ($type == self::VALIDATION_DNS) {
            return $this->selfDNSTest($authorization, $maxAttempts);
        }
        return false;
    }

    /**
     * Validate a challenge
     *
     * @param Challenge $challenge
     * @param int $maxAttempts
     * @return bool
     * @throws FilesystemException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    public function validate(Challenge $challenge, int $maxAttempts = 15): bool
    {
        $this->request(
            $challenge->getUrl(),
            $this->signPayloadKid([
                'keyAuthorization' => $challenge->getToken() . '.' . $this->getDigest()
            ], $challenge->getUrl())
        );

        $data = [];
        do {
            $response = $this->request(
                $challenge->getAuthorizationURL(),
                $this->signPayloadKid(null, $challenge->getAuthorizationURL())
            );
            $data = json_decode((string)$response->getBody(), true);
            if ($maxAttempts > 1 && $data['status'] != 'valid') {
                sleep(ceil(15 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0 && $data['status'] != 'valid');

        return isset($data['status']) && $data['status'] == 'valid';
    }

    /**
     * Return a certificate
     *
     * @param Order $order
     * @param int $maxAttempts number of attempts to fetch an async processed certificate
     * @param int $delay number of seconds to sleep between the attempts to fetch an async processed certificate
     * @param int $respectRetryAfterBelowNSeconds respect "Retry-After" response header if it is below n (=30) seconds.
     * After this, the attempt-delay combination will be applied if the certificate status is still in processing state.
     * @return Certificate
     * @throws CertificateParsingException
     * @throws CertificateSigningRequestException
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    public function getCertificate(
        Order $order,
        int   $maxAttempts = 15,
        int   $delay = 1,
        int   $respectRetryAfterBelowNSeconds = 30
    ): Certificate
    {
        $privateKey = Helper::getNewKey($this->getOption('key_length', 4096));
        $csr = Helper::getCsr($order->getDomains(), $privateKey);
        $der = Helper::toDer($csr);

        $response = $this->request(
            $order->getFinalizeURL(),
            $this->signPayloadKid(
                ['csr' => Helper::toSafeString($der)],
                $order->getFinalizeURL()
            )
        );

        $data = json_decode((string)$response->getBody(), true);

        if (!empty($data['certificate'])) {
            $chain = $this->getCertificateChain($data['certificate']);
        } else {
            $chain = $this->doAsyncOrderFinalization(
                $order,
                $data,
                $response,
                $maxAttempts,
                $delay,
                $respectRetryAfterBelowNSeconds
            );
        }

        if (empty($chain)) {
            throw new GenericYaacException('Could not obtain certificate');
        }

        return new Certificate($privateKey, $csr, $chain);
    }

    /**
     * Asynchronous order finalization for a Let's Encrypt certificate, based on RFC8555.
     * https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2:~:text=%22processing%22:%20The%20certificate%20is%20being%20issued
     *
     * @return string|null chain string or null
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    protected function doAsyncOrderFinalization(
        Order             $initialOrder,
        mixed             $data,
        ResponseInterface $response,
        int               $maxAttempts,
        int               $delay,
        int               $respectRetryAfterBelowNSeconds
    ): string|null
    {
        if ('processing' == $data['status']) {
            $retryAfterLine = $response->getHeaderLine('Retry-After');

            if (!is_numeric($retryAfterLine)) {
                try {
                    $retryAfterLine = (new DateTime($retryAfterLine))->getTimestamp() - time();
                } catch (\Exception $e) {
                    # disable initial Retry-After sleep in case of a parsing error
                    $retryAfterLine = 0;
                }
            }

            $retryAfterSeconds = (int)$retryAfterLine;
            $retryAfterSeconds = match (true) {
                empty($retryAfterSeconds), $retryAfterSeconds < 0 => 0,
                $retryAfterSeconds > $respectRetryAfterBelowNSeconds => $respectRetryAfterBelowNSeconds,
                default => $retryAfterSeconds
            };

            # initial sleep to respect the Retry-After header if not changed by the user
            sleep($retryAfterSeconds);
            do {
                $initialOrder = $this->getOrder($initialOrder->getId());

                if ('valid' == $initialOrder->getStatus()) {
                    return $this->getCertificateChain($initialOrder->getCertificate());
                }

                $maxAttempts--;
                sleep($delay);
            } while ($maxAttempts > 0);
        }
        return null;
    }

    /**
     * Return LE account information
     *
     * @return Account
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    public function getAccount(): Account
    {
        $response = $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'onlyReturnExisting' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );

        $data = json_decode((string)$response->getBody(), true);
        $accountURL = $response->getHeaderLine('Location');
        $date = (new DateTime())->setTimestamp(strtotime($data['createdAt']));
        return new Account($date, ($data['status'] == 'valid'), $accountURL);
    }

    /**
     * Return certificate chain
     *
     * @param string $certificate
     * @return string
     * @throws FilesystemException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    private function getCertificateChain($certificate): string
    {
        $certificateResponse = $this->request(
            $certificate,
            $this->signPayloadKid(null, $certificate)
        );
        return preg_replace('/^[ \t]*[\r\n]+/m', '', (string)$certificateResponse->getBody());
    }

    /**
     * Returns the ACME api configured Guzzle Client
     * @return HttpClient
     */
    protected function getHttpClient(): HttpClient
    {
        if ($this->httpClient === null) {
            $config = [
                'base_uri' => (
                ($this->getOption('mode', self::MODE_LIVE) == self::MODE_LIVE) ?
                    self::DIRECTORY_LIVE : self::DIRECTORY_STAGING),
            ];
            if ($this->getOption('source_ip', false) !== false) {
                $config['curl.options']['CURLOPT_INTERFACE'] = $this->getOption('source_ip');
            }
            $this->httpClient = new HttpClient($config);
        }
        return $this->httpClient;
    }

    /**
     * Returns a Guzzle Client configured for self-test
     * @return HttpClient
     */
    protected function getSelfTestClient(): HttpClient
    {
        return new HttpClient([
            'verify' => false,
            'timeout' => 10,
            'connect_timeout' => 3,
            'allow_redirects' => true,
        ]);
    }

    /**
     * Self HTTP test
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     */
    protected function selfHttpTest(Authorization $authorization, $maxAttempts): bool
    {
        do {
            $maxAttempts--;
            try {
                $response = $this->getSelfTestClient()->request(
                    'GET',
                    'http://' . $authorization->getDomain() . '/.well-known/acme-challenge/' .
                    $authorization->getFile()->getFilename()
                );
                $contents = (string)$response->getBody();
                if ($contents == $authorization->getFile()->getContents()) {
                    return true;
                }
            } catch (GuzzleException $e) {
                // ignore cause the reason could be a not yet fully set-up challenge webserver
            }
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Self DNS test client that uses Cloudflare's DNS API
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     * @throws GuzzleException
     */
    protected function selfDNSTest(Authorization $authorization, $maxAttempts): bool
    {
        do {
            $response = $this->getSelfTestDNSClient()->get(
                '/dns-query',
                [
                    'query' => [
                        'name' => $authorization->getTxtRecord()->getName(),
                        'type' => 'TXT'
                    ]
                ]
            );
            $data = json_decode((string)$response->getBody(), true);
            if (isset($data['Answer'])) {
                foreach ($data['Answer'] as $result) {
                    if (trim($result['data'], "\"") == $authorization->getTxtRecord()->getValue()) {
                        return true;
                    }
                }
            }
            if ($maxAttempts > 1) {
                sleep(ceil(45 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Return the preconfigured client to call Cloudflare's DNS API
     * @return HttpClient
     */
    protected function getSelfTestDNSClient(): HttpClient
    {
        return new HttpClient([
            'base_uri' => 'https://cloudflare-dns.com',
            'connect_timeout' => 10,
            'headers' => [
                'Accept' => 'application/dns-json',
            ],
        ]);
    }

    /**
     * Initialize the client
     * @throws FilesystemException
     * @throws GenericYaacException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     */
    protected function init(): void
    {
        //Load the directories from the LE api
        $response = $this->getHttpClient()->get('/directory');
        $result = Utils::jsonDecode((string)$response->getBody(), true);
        $this->directories = $result;

        //Prepare LE account
        $this->loadKeys();
        $this->tosAgree();
        $this->account = $this->getAccount();
    }

    /**
     * Make sure a private key is in place before calling this function, otherwise a new one will be generated and stored.
     * @throws FilesystemException
     */
    protected function loadKeys(): void
    {
        //Make sure a private key is in place
        if ($this->getFilesystem()->has($this->getPath('account.pem')) === false) {
            $this->getFilesystem()->write(
                $this->getPath('account.pem'),
                Helper::getNewKey($this->getOption('key_length', 4096))
            );
        }
        $privateKey = $this->getFilesystem()->read($this->getPath('account.pem'));
        $privateKey = openssl_pkey_get_private($privateKey);
        $this->privateKeyDetails = openssl_pkey_get_details($privateKey);
    }

    /**
     * Agree to the terms of service
     *
     * @throws FilesystemException
     * @throws GuzzleException
     * @throws OpensslKeyParsingException
     * @throws OpensslSignatureGenerationException
     * @throws GenericYaacException
     */
    protected function tosAgree(): void
    {
        $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'contact' => [
                        'mailto:' . $this->getOption('username'),
                    ],
                    'termsOfServiceAgreed' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );
    }

    /**
     * Get a formatted path
     *
     * @param string|null $path
     * @return string
     */
    protected function getPath(string $path = null): string
    {
        $userDirectory = preg_replace('/[^a-z0-9]+/', '-', strtolower($this->getOption('username')));

        return $this->getOption(
                'basePath',
                'le'
            ) . DIRECTORY_SEPARATOR . $userDirectory . ($path === null ? '' : DIRECTORY_SEPARATOR . $path);
    }

    /**
     * Return the Flysystem filesystem
     * @return Filesystem|null
     */
    protected function getFilesystem(): Filesystem|null
    {
        return $this->filesystem;
    }

    /**
     * Get a defined option
     *
     * @param      $key
     * @param null $default
     *
     * @return mixed|null
     */
    protected function getOption($key, $default = null): mixed
    {
        if (isset($this->config[$key])) {
            return $this->config[$key];
        }

        return $default;
    }

    /**
     * Get key fingerprint
     *
     * @return string
     * @throws FilesystemException|OpensslKeyParsingException
     */
    protected function getDigest(): string
    {
        if ($this->digest === null) {
            $this->digest = Helper::toSafeString(hash('sha256', json_encode($this->getJWKHeader()), true));
        }

        return $this->digest;
    }

    /**
     * Send a request to the LE API
     *
     * @param string $url
     * @param array $payload
     * @param string $method
     * @return ResponseInterface
     * @throws GuzzleException
     */
    protected function request(string $url, array $payload = [], string $method = 'POST'): ResponseInterface
    {
        $response = $this->getHttpClient()->request($method, $url, [
            'json' => $payload,
            'headers' => [
                'Content-Type' => 'application/jose+json',
            ]
        ]);
        $this->nonce = $response->getHeaderLine('replay-nonce');

        return $response;
    }

    /**
     * Get the LE directory path
     *
     * @param string $directory
     *
     * @return mixed
     * @throws GenericYaacException
     */
    protected function getUrl(string $directory): string
    {
        if (isset($this->directories[$directory])) {
            return $this->directories[$directory];
        }

        throw new GenericYaacException('Invalid directory: ' . $directory . ' not listed');
    }

    /**
     * Get the account key
     *
     * @throws FilesystemException|OpensslKeyParsingException
     */
    protected function getAccountKey(): OpenSSLAsymmetricKey
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private(
                $this->getFilesystem()->read($this->getPath('account.pem'))
            );
        }

        if ($this->accountKey === false) {
            throw new OpensslKeyParsingException('Invalid account key');
        }

        return $this->accountKey;
    }

    /**
     * Get the header
     *
     * @return array
     * @throws FilesystemException|OpensslKeyParsingException
     */
    protected function getJWKHeader(): array
    {
        return [
            'e' => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['e']),
            'kty' => 'RSA',
            'n' => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['n']),
        ];
    }

    /**
     * Get JWK envelope
     *
     * @param $url
     * @return array
     * @throws FilesystemException|GuzzleException|OpensslKeyParsingException
     */
    protected function getJWK($url): array
    {
        // requires nonce to be available
        if ($this->nonce === null) {
            $response = $this->getHttpClient()->head($this->directories[self::DIRECTORY_NEW_NONCE]);
            $this->nonce = $response->getHeaderLine('replay-nonce');
        }
        return [
            'alg' => 'RS256',
            'jwk' => $this->getJWKHeader(),
            'nonce' => $this->nonce,
            'url' => $url
        ];
    }

    /**
     * Get KID envelope
     *
     * @param $url
     * @return array
     * @throws GuzzleException
     */
    protected function getKID($url): array
    {
        $response = $this->getHttpClient()->head($this->directories[self::DIRECTORY_NEW_NONCE]);
        $nonce = $response->getHeaderLine('replay-nonce');

        return [
            "alg" => "RS256",
            "kid" => $this->account->getAccountURL(),
            "nonce" => $nonce,
            "url" => $url
        ];
    }

    /**
     * Transform the payload to the JWS format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws FilesystemException|OpensslKeyParsingException|OpensslSignatureGenerationException|GuzzleException
     */
    protected function signPayloadJWK($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getJWK($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");

        if ($result === false) {
            throw new OpensslSignatureGenerationException('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload' => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }

    /**
     * Transform the payload to the KID format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws FilesystemException|OpensslKeyParsingException|OpensslSignatureGenerationException|GuzzleException
     */
    protected function signPayloadKid($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getKID($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");
        if ($result === false) {
            throw new OpensslSignatureGenerationException('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload' => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }
}
