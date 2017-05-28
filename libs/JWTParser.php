<?php

namespace parinpan\fanjwt\libs;

use parinpan\fanjwt\libs\Base64Url;
use parinpan\fanjwt\libs\JWTConfig;
use parinpan\fanjwt\libs\JWTErrors;
use parinpan\fanjwt\libs\JWTGenerator;

/*
    Written by: M. Fachrin Aulia Nasution
    Email: prn@samper.in
    Page: http://samper.in
*/

class JWTParser
{
    public static function parseToken($token)
    {
        $totalParts = 3;
        $tokenParts = explode('.', $token);

        $isValidToken = false;
        $headersDecoded = $payloadDecoded = null;

        if(count($tokenParts) === $totalParts)
        {
            list($headers, $payload, $signature) = $tokenParts;

            $headersDecoded = @json_decode(Base64Url::decode($headers));
            $payloadDecoded = @json_decode(Base64Url::decode($payload));

            if($headersDecoded && $payloadDecoded)
            {
                $secretKey = JWTConfig::SECRET_TOKEN;
                $data = "{$headers}.{$payload}";

                $clientSignature = Base64Url::encode(
                    hash_hmac(
                        'SHA256', $data,
                        $secretKey, true
                    )
                );

                $isValidToken = $clientSignature === $signature;
            }

            if(!$isValidToken)
            {
                throw new \JWTInvalidToken('Token is not match and invalid.');
            }

            return (object) [
                'headers' => $headersDecoded,
                'payload' => $payloadDecoded
            ];
        }
    }
}
