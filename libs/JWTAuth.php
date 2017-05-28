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

	public static function send(Array $props)
	{
		$curl = curl_init();
		header('Content-Type: application/json');

		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_URL, $props['callback']);
		curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query([
			'redir' => $props['redir'],
			'token' => $props['token']
		]));

		$response = @json_decode(
			curl_exec($curl)
		);

		return $response['jwt_token'] === $props['token'] ? $response : false;
	}

	public static function recv(Array $props)
	{
		header('Content-Type: application/json');

		$props = [
			'ssotok' => @$props['ssotok'] ?: null,
			'secured' => @$props['secured'] ?: false,
			'redir' => @$props['redir'] ?: '/'
		];

		$jwtToken = $props['ssotok'];
		$credentials = @JWTParser::parseToken($jwtToken);
		$credentials['jwt_token'] = $jwtToken;

		setcookie(
			'ssotok', $jwtToken,
			$credentials->payload->exp, '/',
			null, $props['secured'], true
		);

		return json_encode($credentials);
	}
}
