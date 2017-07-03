<?php

namespace parinpan\fanjwt\libs;

use parinpan\fanjwt\libs\Base64Url;
use parinpan\fanjwt\libs\JWTConfig;
use parinpan\fanjwt\libs\JWTParser;

class JWTAuth
{
	public static function makeLink(Array $props)
	{
		$query = [
			'redir' => Base64Url::encode($props['redir']),
			'callback' => Base64Url::encode($props['callback'])
		];

		if(isset($props['type']) && $props['type'] == 'logout')
		{
			unset($query['callback']);
		}

		return $props['baseUrl'] . "?" . http_build_query($query);
	}

	public static function communicate($server, $token, \Closure $actionFunc = null)
	{
		$curl = curl_init();

		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_URL, $server);
		curl_setopt($curl, CURLOPT_HTTPHEADER, [
			"Authorization: Bearer {$token}"
		]);

		if(!($response = @json_decode(curl_exec($curl))))
		{
			$response = new \stdClass;
			$response->token = $token;
			$response->logged_in = false;
			$response->connected = false;
		}

		return $actionFunc ? call_user_func($actionFunc, $response) : $response;
	}

	public static function listen()
	{
		$precedenceAuthStr = 'Bearer ';
		$authorizationStr = @getallheaders()['Authorization'];
		$jwtToken = $authorizationStr ? @explode(' ', $authorizationStr)[1] : null;

		if($parsedToken = @JWTParser::parseToken($jwtToken))
		{
			$parsedToken->token = $jwtToken;
		}

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
