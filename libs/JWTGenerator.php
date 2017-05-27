<?php

namespace libs\JWTGenerator;
use libs\Base64Url;

/*
    Written by: M. Fachrin Aulia Nasution
    Email: prn@samper.in
    Page: http://samper.in
*/

class JWTGenerator
{
    private $key;
    private $headers;
	private $payload;
    private $signature;

    const ORIGINAL_ATTR = 1;
    const ENCODED_ATTR = 2;

    public function __construct(array $props = null)
    {
        $this->key = @$props['key'] ?: null;
        $this->headers['original'] = @$props['headers'] ?: [];
        $this->payload['original'] = @$props['payload'] ?: [];
    }

    public function setKey($key)
    {
        $this->key = $key;
        return $this;
    }

    public function setHeaders(array $headers)
    {
        $this->headers['original'] = $headers;
        return $this;
    }

    public function setPayload(array $payload)
    {
        $this->payload['original'] = $payload;
        return $this;
    }

    private function transformData($value, $type)
    {
        if(is_array($value))
        {
            $value = json_encode($value);
        }

        if($type === static::ENCODED_ATTR)
        {
            $value = Base64Url::encode($value);
        }

        return $value;
    }

    public function getHeaders($type)
    {
        return $this->transformData(
            $this->headers['original'],
            $type
        );
    }

    public function getPayload($type)
    {
        return $this->transformData(
            $this->payload['original'],
            $type
        );
    }

    public function getSignature($type)
    {
        $this->headers['encoded'] = $this->getHeaders(static::ENCODED_ATTR);
        $this->payload['encoded'] = $this->getPayload(static::ENCODED_ATTR);

        $this->signature = hash_hmac(
            "SHA256",
            "{$this->headers['encoded']}.{$this->payload['encoded']}",
            $this->key,
            true
        );

        return $this->transformData($this->signature, $type);
    }

    public function getToken()
    {
        $signature = $this->getSignature(static::ENCODED_ATTR);
        $token = $this->headers['encoded'];
        $token.= "." . $this->payload['encoded'];
        $token.= "." . $signature;

        return $token;
    }
}
