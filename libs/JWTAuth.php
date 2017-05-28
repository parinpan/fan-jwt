<?php

namespace parinpan\fanjwt\libs;

use parinpan\fanjwt\libs\Base64Url;
use parinpan\fanjwt\libs\JWTConfig;
use parinpan\fanjwt\libs\JWTParser;

class JWTAuth
{
	public static function send(Array $props)
	{
		
	}

	public static function makeLink(Array $props)
	{
		return $props['baseUrl'] . "?" . http_build_query([
			'redir' => Base64Url::encode($props['redir']),
			'callback' => Base64Url::encode($props['callback'])
		]);
	}

	public static function recv(Array $props)
	{
		$props = [
			'ssotok' => @$props['ssotok'] ?: null,
			'secured' => @$props['secured'] ?: false,
			'redir' => @$props['redir'] ?: '/'
		];

		$jwtToken = $props['ssotok'];
		$credentials = @JWTParser::parseToken($jwtToken);

		setcookie(
			'ssotok', $jwtToken,
			$credentials->payload->exp, '/',
			null, $props['secured'], true
		);

		return header("Location: {$props['redir']}");
	}
}
