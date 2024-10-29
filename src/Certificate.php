<?php

declare(strict_types=1);

namespace Dmcz\AppleAppStore;

use DateTimeInterface;
use OpenSSLCertificate;
use Dmcz\AppleAppStore\Exception\CertificateException;

class Certificate
{
    public function __construct(
        public readonly OpenSSLCertificate $openSSLCertificate,
        public readonly array $data,
    )
    {}

    public function verify(self $publicKey): bool
    {
        return 1 == openssl_x509_verify($this->openSSLCertificate, $publicKey->openSSLCertificate);
    }

    public function verifyEffectiveTime(DateTimeInterface $effectiveTime)
    {
        $effectiveTimestamp = $effectiveTime->getTimestamp();

        return isset($this->data["validFrom_time_t"]) && $this->data["validFrom_time_t"] < $effectiveTimestamp
                && isset($this->data["validTo_time_t"]) && $this->data["validTo_time_t"] > $effectiveTimestamp;
    }

    public function verifyOid(string $oid): bool
    {
        return isset($this->data['extensions'][$oid]);
    }

    public static function fromDER(string $der, bool $isBase64Encoded = false): self
    {
        $base64EncodedDER = $isBase64Encoded ? $der : base64_encode($der);
        $pem = "-----BEGIN CERTIFICATE-----" . PHP_EOL
            . chunk_split(string: $base64EncodedDER, length: 64, separator: PHP_EOL)
            . "-----END CERTIFICATE-----" . PHP_EOL;
        return self::fromPEM($pem);
    }


    public static function fromPEM(string $pem): self
    {
        $openSSLCertificate = openssl_x509_read($pem);
        if ($openSSLCertificate === false) {
            throw new CertificateException("Invalid certificate.");
        }

        $data = openssl_x509_parse($openSSLCertificate);
        if ($data === false) {
            throw new CertificateException("Invalid certificate.");
        }

        return new static(
            $openSSLCertificate,
            $data,
        );
    }
}