<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore;

use Lcobucci\JWT\Signer;
use Carbon\CarbonImmutable;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Validation\Validator;
use Dmcz\AppleAppStore\Constants\Environment;
use Dmcz\AppleAppStore\Constants\OfferDiscountType;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Dmcz\AppleAppStore\Exception\InvalidSignedData;
use Dmcz\AppleAppStore\Exception\CertificateException;

class SignedDataVerifier
{
    public const ALG_NAME = 'ES256';

    /**
     * Mac App Store Receipt Signing
     * @see https://www.apple.com/certificateauthority/Worldwide_Developer_Relations_CPS
     */
    protected const RECEIPT_SIGNER_OID  = '1.2.840.113635.100.6.11.1';

    protected const WWDR_INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

    protected Parser $parser;

    protected Signer $signer;

    /**
     * Undocumented function
     *
     * @param array<Certificate> $rootCertificates 
     * @see https://www.apple.com/certificateauthority/
     */
    public function __construct(
        protected array $rootCertificates,
        protected Environment $environment,
        protected bool $onlineChecks = false,
    ){
        if(empty($rootCertificates)){
            throw new CertificateException("The root certificates is empty");
        }

        $this->parser = new Parser(new JoseEncoder);
        $this->signer = new Sha256();
    }

    public function signedTransaction(string $signedTransaction)
    {
        $data = $this->decode($signedTransaction);
        
        OfferDiscountType::PayAsYouGo;
    }

    public function decode(string $signedData): array
    {   
        try {
            /** @var Plain */
            $jwt = $this->parser->parse($signedData);
        } catch (\Throwable $th) {
            throw new InvalidSignedData("Failed to parse the signed data: " .  $th->getMessage(), $th->getCode(), $th);
        }

        if($this->environment == Environment::Xcode){
            return $jwt->claims()->all();
        }

        $x5c = $jwt->headers()->get('x5c');
        if(empty($x5c)){
            throw new InvalidSignedData("x5c claim is empty");
        }else if(count($x5c) != 3){
            throw new InvalidSignedData("x5c claim is error");
        }

        $alg = $jwt->headers()->get('alg');
        if(empty($alg) || $alg != self::ALG_NAME){
            throw new InvalidSignedData("Algorithm was not" . self::ALG_NAME);
        }

        $signedDate = $jwt->claims()->get('signedDate', $jwt->claims()->get('receiptCreationDate'));
        
        if($this->onlineChecks || empty($signedDate)){
            $effectiveDate = new CarbonImmutable();
        }else{
            $effectiveDate = CarbonImmutable::createFromTimestampMs($signedDate);
        }

        $leafCert = Certificate::fromDER($x5c[0], true);
        $intermediateCert = Certificate::fromDER($x5c[1], true);

        if(!$leafCert->verifyEffectiveTime($effectiveDate) || !$intermediateCert->verifyEffectiveTime($effectiveDate)){
            throw new CertificateException("Certificate expired");
        }

        if(!$leafCert->verifyOid(self::RECEIPT_SIGNER_OID) || !$intermediateCert->verifyOid(self::WWDR_INTERMEDIATE_OID)){
            throw new CertificateException("Verification failure");
        }

        if(!$leafCert->verify($intermediateCert)){
            throw new CertificateException("Verification failure");
        }

        $rootCertificate = null;
        foreach($this->rootCertificates as $cert){
            if($intermediateCert->verify($cert)){
                $rootCertificate = $cert;
                break;
            }
        }

        if(is_null($rootCertificate)){
            throw new CertificateException("Verification failure");
        }


        if($this->onlineChecks){
            // TODO OCSP
        }

        $validator = new Validator();

        $publicKeyResource  = openssl_pkey_get_public($leafCert->openSSLCertificate);
        $publicKeyDetails  = openssl_pkey_get_details($publicKeyResource);
        $publicKeyString = InMemory::plainText($publicKeyDetails['key']);

        if(!$validator->validate($jwt, new SignedWith($this->signer, $publicKeyString))){
            throw new CertificateException("Verification failure");
        }

        return $jwt->claims()->all();
    }

}