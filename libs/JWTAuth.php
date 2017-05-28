<?php

namespace parinpan\fanjwt\libs;

use parinpan\fanjwt\libs\JWTConfig;
use parinpan\fanjwt\libs\JWTParser;

class JWTAuth
{
	public static function send(Array $props)
	{

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
