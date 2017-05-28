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

	public static function recv(Array $props)
	{
		$props = [
			'redir' => @$props['redir'] ?: '/',
			'ssotok' => @$props['ssotok'] ?: false,
			'secured' => @$props['secured'] ?: false,
			'serverLogin' => @$props['serverLogin'] ?: '/',
		];

		if($jwt = @JWTParser::parseToken($props['ssotok']))
		{
			setcookie(
				'ssotok', $props['ssotok'],
				$jwt->payload->exp, '/', false,
				$props['secured'], true
			);
		}

		$redirUrl = $jwt ? @$props['redir'] : @$props['serverLogin'] . "?failed=1";
		header('Content-Type: text/html');
		header('Location: ' . $redirUrl);

		return "Please wait, while we are signing you in....";
	}
}
