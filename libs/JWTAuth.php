<?php

namespace parinpan\fanjwt\libs;

use parinpan\fanjwt\libs\Base64Url;
use parinpan\fanjwt\libs\JWTConfig;
use parinpan\fanjwt\libs\JWTParser;

class JWTAuth
{
	public static function makeLink(Array $props)
	{
		return $props['baseUrl'] . "?" . http_build_query([
			'redir' => Base64Url::encode($props['redir']),
			'callback' => Base64Url::encode($props['callback'])
		]);
	}

	public static function communicate($server, $token)
	{
		$curl = curl_init();

		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_URL, $server);
		curl_setopt($curl, CURLOPT_HTTPHEADER, [
			"Authorization: Bearer {$token}"
		]);

		return @json_decode(curl_exec($curl));
	}

	public static function listen()
	{
		$precedenceAuthStr = 'Authorization: Bearer ';
		$authorizationStr = @getallheaders()['Authorization'];

		$jwtToken = str_replace($precedenceAuthStr, '', $authorizationStr);
		$parsedToken = @JWTParser::parseToken($token);
		$parsedToken['token'] = $jwtToken;

		return $parsedToken;
	}

	public static function recv(Array $props)
	{
		$props = [
			'ssotok' => @$props['ssotok'] ?: false,
			'secured' => @$props['secured'] ?: false,
		];

		if($jwt = @JWTParser::parseToken($props['ssotok']))
		{
			setcookie(
				'ssotok', $props['ssotok'],
				$jwt->payload->exp, '/', false,
				$props['secured'], true
			);
		}

		return true;
	}
}
