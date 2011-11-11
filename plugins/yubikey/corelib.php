<?php

define('YK_SEC_NORMAL_USERNAME', 1);
define('YK_SEC_NORMAL_PASSWORD', 2);
define('YK_SEC_ELEV_USERNAME', 4);
define('YK_SEC_ELEV_PASSWORD', 8);
define('YK_SEC_ALLOW_NO_OTP', 16);

define('YK_DEFAULT_VERIFY_URL', 'http://api.yubico.com/wsapi/verify');

function generate_yubikey_field($name = 'yubikey_otp', $value = false)
{
	global $lang;
	
	$fid = substr(sha1(microtime() . mt_rand()), 0, 12);
	$class = $value ? 'wasfull' : 'wasempty';
	$html = '<input id="yubifield' . $fid . '" class="' . $class . '" type="hidden" name="' . $name . '" value="' . ( is_string($value) ? $value : '' ) . '" />';
	$html .= '<noscript><input type="text" name="' . $name . '" class="yubikey_noscript" value="' . ( is_string($value) ? $value : '' ) . '" /> </noscript>';
	if ( $value )
	{
		$html .= '<span id="yubistat' . $fid . '" class="yubikey_status enrolled">' . $lang->get('yubiauth_ctl_status_enrolled') . '</span>';
		$atext = $lang->get('yubiauth_ctl_btn_change_key');
		$classadd = ' abutton_green';
	}
	else
	{
		$html .= '<span id="yubistat' . $fid . '" class="yubikey_status empty">' . $lang->get('yubiauth_ctl_status_empty') . '</span>';
		$atext = $lang->get('yubiauth_ctl_btn_enroll');
		$classadd = '';
	}
	
	$html .= ' <span class="yubikey_pubkey">';
	if ( !empty($value) )
		$html .= htmlspecialchars(substr($value, 0, 12));
	$html .= '</span> ';
	
	$html .= ' <a class="abutton' . $classadd . ' yubikey_enroll" onclick="yk_mb_init(\'yubifield' . $fid . '\', \'yubistat' . $fid . '\'); return false;" href="#enroll">' . $atext . '</a>';
	if ( $value )
	{
		$html .= ' <a class="abutton abutton_red yubikey_enroll" onclick="yk_clear(\'yubifield' . $fid . '\', \'yubistat' . $fid . '\'); return false;" href="#enroll">'
 						. $lang->get('yubiauth_ctl_btn_clear') .
 						'</a>';
	}
	
	return $html;
}

function yubikey_validate_otp($otp)
{
	$api_key = getConfig('yubikey_api_key');
	$api_id  = getConfig('yubikey_api_key_id');
	// Don't require an API key or user ID to be installed if we're using local YMS
	if ( !(getConfig('yubikey_use_local_yms', 0) && defined('YMS_INSTALLED')) && (!$api_key || !$api_id) )
	{
		return array(
				'success' => false,
				'error' => 'missing_api_key'
			);
	}
	if ( !preg_match('/^[cbdefghijklnrtuv]{44}$/', $otp) )
	{
		return array(
				'success' => false,
				'error' => 'otp_invalid_chars'
			);
	}
	// are we using local YMS?
	if ( getConfig('yubikey_use_local_yms', 0) && defined('YMS_INSTALLED') )
	{
		$result = yms_validate_otp($otp, $api_id);
		if ( $result == 'OK' )
		{
			return array(
					'success' => true
				);
		}
		else
		{
			return array(
				'success' => false,
				'error' => strtolower("response_{$result}")
			);
		}
	}
	// make HTTP request
	require_once( ENANO_ROOT . '/includes/http.php' );
	$auth_url = getConfig('yubikey_auth_server', YK_DEFAULT_VERIFY_URL);
	$auth_url = preg_replace('#^https?://#i', '', $auth_url);
	if ( !preg_match('#^(\[?[a-z0-9-:]+(?:\.[a-z0-9-:]+\]?)*)(?::([0-9]+))?(/.*)$#U', $auth_url, $match) )
	{
		return array(
				'success' => false,
				'error' => 'invalid_auth_url'
			);
	}
	$auth_server =& $match[1];
	$auth_port = ( !empty($match[2]) ) ? intval($match[2]) : 80;
	$auth_uri =& $match[3];
	try
	{
		$req = new Request_HTTP($auth_server, $auth_uri, 'GET', $auth_port);
		$req->add_get('id', strval($api_id));
		$req->add_get('otp', $otp);
		$req->add_get('h', yubikey_sign($req->parms_get));
	
		$response = $req->get_response_body();
	}
	catch ( Exception $e )
	{
		return array(
				'success' => false,
				'error' => 'http_failed',
				'http_error' => $e->getMessage()
			);
	}
	
	if ( $req->response_code != HTTP_OK )
	{
		return array(
				'success' => false,
				'error' => 'http_response_error'
			);
	}
	$response = trim($response);
	if ( !preg_match_all('/^([a-z0-9_]+)=(.*?)\r?$/m', $response, $matches) )
	{
		return array(
				'success' => false,
				'error' => 'malformed_response'
			);
	}
	$response = array();
	foreach ( $matches[0] as $i => $_ )
	{
		$response[$matches[1][$i]] = $matches[2][$i];
	}
	// make sure we have a status
	if ( !isset($response['status']) )
	{
		return array(
				'success' => false,
				'error' => 'response_missing_status'
			);
	}
	// verify response signature
	// MISSING_PARAMETER is the ONLY situation under which an unsigned response is acceptable
	if ( $response['status'] !== 'MISSING_PARAMETER' )
	{
		if ( !isset($response['h']) )
		{
			return array(
					'success' => false,
					'error' => 'response_missing_sig'
				);
		}
		if ( yubikey_sign($response) !== $response['h'] )
		{
			return array(
					'success' => false,
					'error' => 'response_invalid_sig'
				);
		}
	}
	if ( $response['status'] === 'OK' )
	{
		if ( yubikey_verify_timestamp($response['t']) )
		{
			return array(
					'success' => true
				);
		}
		else
		{
			return array(
					'success' => false,
					'error' => 'timestamp_check_failed'
				);
		}
	}
	else
	{
		return array(
				'success' => false,
				'error' => strtolower("response_{$response['status']}")
			);
	}
}

function yubikey_sign($arr, $use_api_key = false)
{
	static $api_key = false;
	
	ksort($arr);
	
	if ( !$use_api_key )
	{
		if ( !$api_key )
		{
			$api_key = getConfig('yubikey_api_key');
			$api_key = hexencode(base64_decode($api_key), '', '');
		}
		$use_api_key = $api_key;
	}
	/*
	else
	{
		$use_api_key = hexencode(base64_decode($use_api_key), '', '');
	}
	*/
	
	foreach ( array('h', 'title', 'auth', 'do') as $key )
	{
		if ( isset($arr[$key]) )
			unset($arr[$key]);
	}
	
	$req = array();
	foreach ( $arr as $key => $val )
	{
		$req[] = "$key=$val";
	}
	$req = implode('&', $req);
	
	$sig = hmac_sha1($req, $use_api_key);
	$sig = hexdecode($sig);
	$sig = base64_encode($sig);
	
	return $sig;
}

/**
 * Validate the timestamp returned in a Yubico API response. Borrowed from Drupal and backported for friendliness with earlier versions of PHP.
 * @param string Yubico timestamp
 * @return bool True if valid, false otherwise
 */

function yubikey_verify_timestamp($timestamp)
{
	$tolerance = intval(getConfig('yubikey_api_ts_tolerance', 150));
	
	$now = time();
	$timestamp_seconds = yk_strtotime($timestamp);

	if ( !$timestamp || !$now || !$timestamp_seconds )
	{
		return false;
	}

	if ( ( $timestamp_seconds + $tolerance ) > $now && ( $timestamp_seconds - $tolerance ) < $now )
	{
		return true;
	}

	return false;
}

function yk_strtotime($timestamp)
{
	if ( !preg_match('/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z[0-9]+)?$/', $timestamp, $match) )
		return 0;
	
	$hour = intval($match[4]);
	$minute = intval($match[5]);
	$second = intval($match[6]);
	$month = intval($match[2]);
	$day = intval($match[3]);
	$year = intval($match[1]);
	
	return gmmktime($hour, $minute, $second, $month, $day, $year);
}

$plugins->attachHook('compile_template', 'yubikey_attach_headers($this);');

function yubikey_attach_headers(&$template)
{
	global $db, $session, $paths, $template, $plugins; // Common objects
	
	if ( getConfig('yubikey_enable', '1') != '1' )
		return true;
	
	$template->add_header('<script type="text/javascript" src="' . scriptPath . '/plugins/yubikey/yubikey.js"></script>');
	$template->add_header('<link rel="stylesheet" type="text/css" href="' . scriptPath . '/plugins/yubikey/yubikey.css" />');
	// config option for all users have yubikey
	$user_flags = 0;
	$yk_enabled = 0;
	if ( $session->user_logged_in )
	{
		$q = $db->sql_query('SELECT COUNT(y.yubi_uid) > 0, u.user_yubikey_flags FROM ' . table_prefix . "yubikey AS y LEFT JOIN " . table_prefix . "users AS u ON ( u.user_id = y.user_id ) WHERE y.user_id = {$session->user_id} GROUP BY u.user_id, u.user_yubikey_flags;");
		if ( !$q )
			$db->_die();
		
		list($yk_enabled, $user_flags) = $db->fetchrow_num();
		$db->free_result();
	}
	$yk_enabled = intval($yk_enabled);
	$user_flags = intval($user_flags);
	
	$template->add_header('<script type="text/javascript">var yk_reg_require_otp = ' . getConfig('yubikey_reg_require_otp', '0') . '; var yk_user_enabled = ' . $yk_enabled . '; var yk_user_flags = ' . $user_flags . ';</script>');
}

