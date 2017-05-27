<?php

namespace libs\Base64Url;

final class Base64Url
{
    public static function encode($string)
    {
        return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
    }

    public static function decode($string)
    {
        return base64_decode(strtr($string, '-_', '+/'));
    }
}