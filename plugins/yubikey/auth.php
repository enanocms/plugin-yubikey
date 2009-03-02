<?php

if ( getConfig('yubikey_enable', '1') != '1' )
    return true;

// hook into auth
$plugins->attachHook('login_process_userdata_json', 'return yubikey_auth_hook_json($userinfo, $req["level"], @$req["remember"]);');
// hook into special page init
$plugins->attachHook('session_started', 'yubikey_add_special_pages();');

function yubikey_auth_hook_json(&$userdata, $level, $remember)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  global $lang;
  
  $do_validate_otp = false;
  $do_validate_user = false;
  $do_validate_pass = false;
  
  $user_flag = ( $level >= USER_LEVEL_CHPREF ) ? YK_SEC_ELEV_USERNAME : YK_SEC_NORMAL_USERNAME;
  $pass_flag = ( $level >= USER_LEVEL_CHPREF ) ? YK_SEC_ELEV_PASSWORD : YK_SEC_NORMAL_PASSWORD;
  
  $auth_log_prefix = ( $level >= USER_LEVEL_CHPREF ) ? 'admin_' : '';
  
  // Sort of a hack: if the password looks like an OTP and the OTP field is empty, use the password as the OTP
  if ( empty($userdata['yubikey_otp']) && preg_match('/^[cbdefghijklnrtuv]{44}$/', $userdata['password'] ) )
  {
    $userdata['yubikey_otp'] = $userdata['password'];
  }
  
  if ( !empty($userdata['username']) )
  {
    // get flags
    $q = $db->sql_query('SELECT user_id, user_yubikey_flags FROM ' . table_prefix . "users WHERE " . ENANO_SQLFUNC_LOWERCASE . "(username) = '" . $db->escape(strtolower($userdata['username'])) . "';");
    if ( !$q )
      $db->die_json();
    
    if ( $db->numrows() < 1 )
    {
      // Username not found - let the main login function handle it
      $db->free_result();
      return null;
    }
    list($user_id, $flags) = $db->fetchrow_num();
    $flags = intval($flags);
    // At the point the username is validated.
    $do_validate_user = false;
    $do_validate_pass = $flags & $pass_flag;
    if ( empty($userdata['yubikey_otp']) )
    {
      // no OTP was provided
      // make sure the user has allowed logging in with no OTP
      if ( !($flags & YK_SEC_ALLOW_NO_OTP) )
      {
        // We also might have no Yubikeys enrolled.
        $q = $db->sql_query('SELECT 1 FROM ' . table_prefix . "yubikey WHERE user_id = $user_id;");
        if ( !$q )
          $db->die_json();
        
        if ( $db->numrows() > 0 )
        {
          // Yep at least one key is enrolled.
          // I don't think these should be logged because they'll usually just be innocent mistakes.
          $db->free_result();
          return array(
              'mode' => 'error',
              'error' => 'yubiauth_err_must_have_otp'
            );
        }
        // Nope, no keys enrolled, user hasn't enabled Yubikey support
        $db->free_result();
      }
      // we're ok, use normal password auth
      return null;
    }
    else
    {
      // user did enter an OTP
      $do_validate_otp = true;
    }
  }
  else if ( !empty($userdata['yubikey_otp']) )
  {
    // we have an OTP, but no username to work with
    $yubi_uid = substr($userdata['yubikey_otp'], 0, 12);
    if ( !preg_match('/^[cbdefghijklnrtuv]{12}$/', $yubi_uid ) )
    {
      return array(
          'mode' => 'error',
          'error' => 'yubiauth_err_invalid_otp'
        );
    }
    $q = $db->sql_query('SELECT u.user_id, u.username, u.user_yubikey_flags FROM ' . table_prefix . "users AS u\n"
                      . "  LEFT JOIN " . table_prefix . "yubikey AS y\n"
                      . "    ON ( y.user_id = u.user_id )\n"
                      . "  WHERE y.yubi_uid = '$yubi_uid'\n"
                      . "  GROUP BY u.user_yubikey_flags;");
    if ( !$q )
      $db->_die();
    
    if ( $db->numrows() < 1 )
    {
      if ( !$do_validate_pass )
        $session->sql('INSERT INTO ' . table_prefix . "logs(log_type,action,time_id,date_string,author,edit_summary,page_text) VALUES\n"
                   . '  (\'security\', \'' . $auth_log_prefix . 'auth_bad\', '.time().', \''.enano_date('d M Y h:i a').'\', \'(Yubikey)\', '
                      . '\''.$db->escape($_SERVER['REMOTE_ADDR']).'\', ' . intval($level) . ')');
      
      return array(
          'mode' => 'error',
          'error' => 'yubiauth_err_key_not_authorized'
        );
    }
    
    list($user_id, $username, $flags) = $db->fetchrow_num();
    $do_validate_otp = true;
    $do_validate_user = $flags & $user_flag;
    $do_validate_pass = $flags & $pass_flag;
  }
  else
  {
    // Nothing - no username or OTP. This request can't be used; throw it out.
    return array(
        'mode' => 'error',
        'error' => 'yubiauth_err_nothing_provided'
      );
  }
  if ( $do_validate_otp )
  {
    // We need to validate the OTP.
    $otp_check = yubikey_validate_otp($userdata['yubikey_otp']);
    if ( !$otp_check['success'] )
    {
      if ( !$do_validate_pass )
        $session->sql('INSERT INTO ' . table_prefix . "logs(log_type,action,time_id,date_string,author,edit_summary,page_text) VALUES\n"
                   . '  (\'security\', \'' . $auth_log_prefix . 'auth_bad\', '.time().', \''.enano_date('d M Y h:i a').'\', \'(Yubikey)\', '
                      . '\''.$db->escape($_SERVER['REMOTE_ADDR']).'\', ' . intval($level) . ')');
      return array(
          'mode' => 'error',
          'error' => 'yubiauth_err_' . $otp_check['error']
        );
    }
  }
  if ( $do_validate_user )
  {
    if ( empty($username) )
    {
      return array(
          'mode' => 'error',
          'error' => 'yubiauth_err_must_have_username'
        );
    }
    if ( strtolower($username) !== strtolower($userdata['username']) )
    {
      // Username incorrect
      if ( !$do_validate_pass )
        $session->sql('INSERT INTO ' . table_prefix . "logs(log_type,action,time_id,date_string,author,edit_summary,page_text) VALUES\n"
                   . '  (\'security\', \'' . $auth_log_prefix . 'auth_bad\', '.time().', \''.enano_date('d M Y h:i a').'\', \'(Yubikey)\', '
                      . '\''.$db->escape($_SERVER['REMOTE_ADDR']).'\', ' . intval($level) . ')');
      return array(
          'mode' => 'error',
          'error' => 'invalid_credentials'
        );
    }
  }
  // Do we need to have the password validated?
  if ( $do_validate_pass )
  {
    if ( empty($userdata['password']) )
    {
      return array(
          'mode' => 'error',
          'error' => 'yubiauth_err_must_have_password'
        );
    }
    // Yes; return and let the login API continue
    return null;
  }
  else
  {
    // No password required; validated, issue session key
    $session->sql('INSERT INTO ' . table_prefix . "logs(log_type,action,time_id,date_string,author,edit_summary,page_text) VALUES\n"
                   . '  (\'security\', \'' . $auth_log_prefix . 'auth_good\', '.time().', \''.enano_date('d M Y h:i a').'\', \'' . $db->escape($userdata['username']) . '\', '
                      . '\''.$db->escape($_SERVER['REMOTE_ADDR']).'\', ' . intval($level) . ')');
        
    $q = $db->sql_query('SELECT password FROM ' . table_prefix . "users WHERE user_id = $user_id;");
    if ( !$q )
      $db->_die();
    
    list($password) = $db->fetchrow_num();
    $db->free_result();
    
    $session->register_session($user_id, $userdata['username'], $password, $level, $remember);
    return true;
  }
}

function yubikey_add_special_pages()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  global $lang;
  
  if ( getConfig('yubikey_enable', '1') != '1' )
    return true;
  
  $paths->add_page(array(
      'name' => $lang->get('yubiauth_specialpage_yubikey'),
      'urlname' => 'Yubikey',
      'namespace' => 'Special',
      'visible' => 0, 'protected' => 0, 'comments_on' => 0, 'special' => 0
    ));
}

function page_Special_Yubikey()
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  
  header('Content-type: text/javascript');
  /*
  if ( isset($_GET['validate_otp']) )
  {
    echo enano_json_encode(yubikey_validate_otp($_GET['validate_otp']));
    return true;
  }
  */
  if ( isset($_GET['get_flags']) || isset($_POST['get_flags']) )
  {
    $yubi_uid = substr($_REQUEST['get_flags'], 0, 12);
    if ( !preg_match('/^[cbdefghijklnrtuv]{12}$/', $yubi_uid) )
    {
      return print enano_json_encode(array(
          'mode' => 'error',
          'error' => 'invalid_otp'
        ));
    }
    $q = $db->sql_query('SELECT u.user_yubikey_flags FROM ' . table_prefix . "users AS u\n"
                      . "  LEFT JOIN " . table_prefix . "yubikey AS y\n"
                      . "    ON ( y.user_id = u.user_id )\n"
                      . "  WHERE y.yubi_uid = '$yubi_uid'\n"
                      . "  GROUP BY u.user_yubikey_flags;");
    if ( !$q )
      $db->_die();
    
    if ( $db->numrows() < 1 )
    {
      return print enano_json_encode(array(
          'mode' => 'error',
          'error' => 'key_not_authorized'
        ));
    }
    
    list($flags) = $db->fetchrow_num();
    
    echo enano_json_encode(array(
        // We strip YK_SEC_ALLOW_NO_OTP here for security reasons.
        'flags' => intval($flags & ~YK_SEC_ALLOW_NO_OTP)
      ));
    
    return true;
  }
}

