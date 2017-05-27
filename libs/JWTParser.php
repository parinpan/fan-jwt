<?php

require_once('Base64Url.php');
require_once('JWTErrors.php');
require_once('JWTGenerator.php');

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

$token = (new JWTGenerator())
 ->setKey('391972E79C30BB5C2A8941E34129332C001E99E0D5AE90662EF7737352AD9651')
 ->setHeaders([
     'alg' => 'HS256',
     'typ' => 'JWT'
 ])
 ->setPayload([
     'name' => 'hahahahah'
 ])
 ->getToken();

 var_dump($token, JWTParser::parseToken($token));
