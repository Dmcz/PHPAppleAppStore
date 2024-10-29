<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore;

use Carbon\CarbonImmutable;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Key;
use GuzzleHttp\RequestOptions;
use GuzzleHttp\ClientInterface;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use GuzzleHttp\Client as GuzzleHttpClient;
use GuzzleHttp\Exception\BadResponseException;
use Dmcz\AppleAppStore\Exception\ApiErrorException;
use Dmcz\AppleAppStore\Exception\UnauthenticatedException;
use Dmcz\AppleAppStore\Exception\InvalidApiResponseException;

class Client
{
    private const SENDBOX_HOST = 'https://api.storekit-sandbox.itunes.apple.com';

    private const PRODUCTION_HOST = 'https://api.storekit.itunes.apple.com';

    protected string $bundleId;
    protected string $issureId;
    protected string $privateKeyId;
    protected bool $sandbox;
    protected int $tokenTTL;

    private Key $privateKey;

    private Signer $signer;

    private ClientInterface $client;

    /**
     * Auth Token
     * Note that the JWT is valid for up to one hour after the time you indicate in the iat field, or it expires sooner if you set the exp field for an earlier time.
     */
    private ?Token $token = null;

    public function __construct(
        string $bundleId,
        string $issureId,
        string $privateKeyId,
        string $privateKey,
        bool $sandbox = false,
        int $tokenTTL = 60,
        ?ClientInterface $client = null,
    ){
        $this->signer = new Sha256();

        $this->setBundleId($bundleId);
        $this->setIssureId($issureId);
        $this->setPrivateKey($privateKeyId, $privateKey);
        $this->setSandbox($sandbox);
        $this->setTokenTTL($tokenTTL);

        $this->client = $client ?? new GuzzleHttpClient();
    }

    public function setBundleId(string $bundleId): void
    {
        $this->bundleId = $bundleId;
    }

    public function setIssureId(string $issureId): void
    {
        $this->issureId = $issureId;
    }

    public function setPrivateKey(string $id, string $key): void
    {
        $this->privateKeyId = $id;
        $this->privateKey = InMemory::plainText($key);
        $this->token = null;
    }

    public function setSandbox(bool $val): void
    {
        $this->sandbox = $val;
    }

    public function setTokenTTL(int $ttl): void
    {
        $this->tokenTTL = $ttl;
        $this->token = null;
    }

    public function getTransactionInfo(string $transactionId)
    {
        $url = $this->buildUrl('inApps/v1/transactions', $transactionId);

        $resp = $this->get($url);

        $result = json_decode((string) $resp->getBody());

        if(!isset($result->signedTransactionInfo)){
            throw new InvalidApiResponseException('The "Get Transaction Info" API response is missing the required field "signedTransactionInfo"');
        }

        $res = $resp->signedTransactionInfo;

        return $res;
    }

    protected function buildUrl(string ...$args): string
    {
        return ($this->sandbox?self::SENDBOX_HOST:self::PRODUCTION_HOST) .  '/' . implode('/', $args);
    }

    protected function getAuthorization(): string
    {   
        // The token does not exist or will expire soon(refresh token 30 seconds in advance)
        if (! $this->token || $this->token->hasBeenIssuedBefore(CarbonImmutable::now()->subSeconds($this->tokenTTL - 30))) {
            $this->token = $this->generateAuthToken();
        }

        return 'Bearer ' . $this->token->toString();
    }

    protected function generateAuthToken(): Token
    {
        $issuedAt = new CarbonImmutable();

        return (new JwtFacade())->issue(
            $this->signer,
            $this->privateKey,
            fn (
                Builder $builder,
            ): Builder => $builder
                ->withHeader('kid', $this->privateKeyId)
                ->issuedBy($this->issureId)
                ->issuedAt($issuedAt)
                ->expiresAt($issuedAt->addSeconds($this->tokenTTL))
                ->withClaim('bid', $this->bundleId)
                ->permittedFor('appstoreconnect-v1')
        );
    }

    protected function get(string $url)
    {
        return $this->request('GET', $url, [
            RequestOptions::HEADERS => [
                'Authorization' => $this->getAuthorization(),
                'Content-type' => 'application/json',
            ],
        ]);
    }

    protected function request(string $method, string $url, array $options)
    {
        try {
            $resp = $this->client->request($method, $url, $options);
            return $resp; 

        } catch (BadResponseException $e) {
            if($e->getResponse()->getStatusCode() == 401){
                throw new UnauthenticatedException("Unauthenticated", 401, $e);
            }

            $content = (string) $e->getResponse()->getBody();
            if(empty($content)){
                $result = json_decode($content);
                if($result !== false){
                    if(isset($result->errorMessage) && isset($result->errorCode) ){
                        throw new ApiErrorException((string) $result->errorMessage, (int) $result->errorCode, $e);
                    }
                }
            }

            throw $e;
        }
    }
}