<?php

namespace libs\JWTParser;

use libs\Base64Url;
use libs\JWTErrors;
use libs\JWTGenerator;

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
                $jwtConfig = require_once('../config/jwt.php');
                $secretKey = $jwtConfig['secret_key'];
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
