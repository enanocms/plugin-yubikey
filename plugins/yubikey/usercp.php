<?php

if ( getConfig('yubikey_enable', '1') != '1' )
  return true;

$plugins->attachHook("userprefs_jbox", "yubikey_ucp_setup();");
$plugins->attachHook("userprefs_body", "return yubikey_user_cp(\$section);");
$plugins->attachHook("login_form_html", "yubikey_inject_html_login();");
$plugins->attachHook("ucp_register_form", "yubikey_inject_registration_form();");
$plugins->attachHook("ucp_register_validate", "yubikey_register_validate(\$error);");
$plugins->attachHook("user_registered", "yubikey_register_insert_key(\$user_id);");

function yubikey_ucp_setup()
{
  userprefs_menu_add('usercp_sec_profile', 'yubiucp_panel_title', makeUrlNS('Special', 'Preferences/Yubikey') . '" onclick="ajaxLoginNavTo(\'Special\', \'Preferences/Yubikey\', '.USER_LEVEL_CHPREF.'); return false;');
}

function yubikey_user_cp($section)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  global $lang;
  
  if ( $section !== 'Yubikey' )
    return false;
  
  if ( $session->auth_level < USER_LEVEL_CHPREF )
  {
    redirect(makeUrlNS('Special', 'Login/' . $paths->fullpage, 'level=' . USER_LEVEL_CHPREF, true), 'Authentication required', 'You need to re-authenticate to access this page.', 0);
  }
  
  $count_enabled = intval(getConfig('yubikey_enroll_limit', '3'));
  
  if ( isset($_POST['submit']) )
  {
    csrf_request_confirm();
    
    $keys = array();
    if ( isset($_POST['yubikey_enable']) )
    {
      for ( $i = 0; $i < $count_enabled; $i++ )
      {
        if ( !empty($_POST["yubikey_otp_$i"]) )
        {
          $ckey =& $_POST["yubikey_otp_$i"];
          if ( preg_match('/^[cbdefghijklnrtuv]{12,44}$/', $ckey) )
          {
            $ckey = substr($ckey, 0, 12);
            $keys[] = $ckey;
          }
          unset($ckey);
        }
      }
    }
    // Check for double enrollment
    $keys_check = "yubi_uid = '" . implode("' OR yubi_uid = '", $keys) . "'";
    $q = $db->sql_query('SELECT yubi_uid FROM ' . table_prefix . "yubikey WHERE ( $keys_check ) AND user_id != {$session->user_id};");
    if ( !$q )
      $db->_die();
    
    if ( $db->numrows() > 0 )
    {
      echo '<div class="error-box" style="margin: 0 0 10px 0;">' . $lang->get('yubiucp_err_double_enrollment') . '</div>';
      while ( $row = $db->fetchrow() )
      {
        foreach ( $keys as $i => $key )
        {
          if ( $key == $row['yubi_uid'] )
          {
            unset($keys[$i]);
          }
        }
      }
      $keys = array_values($keys);
    }
    $db->free_result();
    
    // Remove all currently registered keys
    $q = $db->sql_query('DELETE FROM ' . table_prefix . "yubikey WHERE user_id = {$session->user_id};");
    if ( !$q )
      $db->_die();
    
    // Enroll any new keys
    if ( !empty($keys) )
    {
      $query = 'INSERT INTO ' . table_prefix . "yubikey(user_id, yubi_uid) VALUES\n  " .
                 "( $session->user_id, '" . implode("' ),\n  ( $session->user_id, '", $keys) . "' );";
      if ( !$db->sql_query($query) )
        $db->_die();
    }
    
    // Calculate flags
    $yubi_flags = 0;
    $yubi_flags |= intval($_POST['login_normal_flags']);
    $yubi_flags |= intval($_POST['login_elev_flags']);
    $yubi_flags |= ( isset($_POST['allow_no_yubikey']) ) ? YK_SEC_ALLOW_NO_OTP : 0;
    
    // update flags
    $q = $db->sql_query('UPDATE ' . table_prefix . "users SET user_yubikey_flags = $yubi_flags WHERE user_id = {$session->user_id};");
    if ( !$q )
      $db->_die();
  }
  else
  {
    // Fetch flags
    $q = $db->sql_query('SELECT user_yubikey_flags FROM ' . table_prefix . "users WHERE user_id = {$session->user_id};");
    if ( !$q )
      $db->_die();
    
    list($yubi_flags) = $db->fetchrow_num();
    $yubi_flags = intval($yubi_flags);
    // Fetch user's authorized keys from the DB
    $q = $db->sql_query('SELECT yubi_uid FROM ' . table_prefix . "yubikey WHERE user_id = {$session->user_id};");
    if ( !$q )
      $db->_die();
    
    $keys = array();
    while ( $row = $db->fetchrow() )
    {
      $keys[] = $row['yubi_uid'];
    }
    $db->free_result();
  }
  
  while ( count($keys) < $count_enabled )
  {
    $keys[] = false;
  }
  
  $enable_checked = ( $keys[0] === false && !isset($_POST['yubikey_enable']) ) ? '' : 'checked="checked"';
  $displaytable = ( $keys[0] === false && !isset($_POST['yubikey_enable']) ) ? 'none' : 'block';
  
  $check_normal_keyonly = ( !($yubi_flags & YK_SEC_NORMAL_USERNAME) && !($yubi_flags & YK_SEC_NORMAL_PASSWORD) ) ? 'checked="checked" ' : '';
  $check_normal_username = ( ($yubi_flags & YK_SEC_NORMAL_USERNAME) && !($yubi_flags & YK_SEC_NORMAL_PASSWORD) ) ? 'checked="checked" ' : '';
  $check_normal_userandpw = ( ($yubi_flags & YK_SEC_NORMAL_USERNAME) && ($yubi_flags & YK_SEC_NORMAL_PASSWORD) ) ? 'checked="checked" ' : '';

  $check_elev_keyonly = ( !($yubi_flags & YK_SEC_ELEV_USERNAME) && !($yubi_flags & YK_SEC_ELEV_PASSWORD) ) ? 'checked="checked" ' : '';
  $check_elev_username = ( ($yubi_flags & YK_SEC_ELEV_USERNAME) && !($yubi_flags & YK_SEC_ELEV_PASSWORD) ) ? 'checked="checked" ' : '';
  $check_elev_userandpw = ( ($yubi_flags & YK_SEC_ELEV_USERNAME) && ($yubi_flags & YK_SEC_ELEV_PASSWORD) ) ? 'checked="checked" ' : '';  
  
  ?>
  <h3 style="margin-top: 0;"><?php echo $lang->get('yubiucp_panel_title'); ?></h3>
  
  <form action="<?php echo makeUrlNS('Special', 'Preferences/Yubikey'); ?>" method="post">
  
  <div>
    <table border="0" cellpadding="4" width="100%">
      <tr>
        <td style="width: 50%; text-align: right;">
          <?php echo $lang->get('yubiucp_field_enable_title'); ?><br />
          <small><?php echo $lang->get('yubiucp_field_enable_hint'); ?></small>
        </td>
        <td style="width: 50%;">
          <label>
            <input type="checkbox" name="yubikey_enable" onclick="if ( $(this).attr('checked') ) $('#yk_useroptions').show('blind'); else $('#yk_useroptions').hide('blind');" <?php echo $enable_checked; ?> />
            <?php echo $lang->get('yubiucp_field_enable'); ?>
          </label>
        </td>
      </tr>
    </table>
    <table border="0" cellpadding="4" width="100%" id="yk_useroptions" style="display: <?php echo $displaytable ?>;">
      <tr class="yk_alt1">
      <td style="width: 50%; text-align: right;">
          <?php echo $lang->get('yubiucp_field_keys_title'); ?><br />
          <small><?php
          echo $lang->get('yubiucp_field_keys_hint');
          if ( $count_enabled > 1 )
          {
            echo ' ';
            echo $lang->get('yubiucp_field_keys_maximum', array('max' => $count_enabled));
          }
          ?></small>
        </td>
        <td style="width: 50%;">
          <?php
          for ( $i = 0; $i < $count_enabled; $i++ )
          {
            echo '<p>' . generate_yubikey_field('yubikey_otp_' . $i, $keys[$i]) . '</p>';
          }
          ?>
        </td>
      </tr>
      <tr>
        <td style="width: 50%; text-align: right;">
          <?php echo $lang->get('yubiucp_field_normal_flags'); ?>
        </td>
        <td>
          <label>
            <input type="radio" name="login_normal_flags" value="0" <?php echo $check_normal_keyonly; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_keyonly'); ?>
          </label>
          
          <br />
          
          <label>
            <input type="radio" name="login_normal_flags" value="<?php echo strval(YK_SEC_NORMAL_USERNAME); ?>" <?php echo $check_normal_username; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_username'); ?>
          </label>
          
          <br />
          
          <label>
            <input type="radio" name="login_normal_flags" value="<?php echo strval(YK_SEC_NORMAL_USERNAME | YK_SEC_NORMAL_PASSWORD); ?>" <?php echo $check_normal_userandpw; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_userandpw'); ?>
          </label>
        </td>
      </tr>
      <tr class="yk_alt1">
        <td style="width: 50%; text-align: right;">
          <?php echo $lang->get('yubiucp_field_elev_flags'); ?>
        </td>
        <td>
          <label>
            <input type="radio" name="login_elev_flags" value="0" <?php echo $check_elev_keyonly; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_keyonly'); ?>
          </label>
          
          <br />
          
          <label>
            <input type="radio" name="login_elev_flags" value="<?php echo strval(YK_SEC_ELEV_USERNAME); ?>" <?php echo $check_elev_username; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_username'); ?>
          </label>
          
          <br />
          
          <label>
            <input type="radio" name="login_elev_flags" value="<?php echo strval(YK_SEC_ELEV_USERNAME | YK_SEC_ELEV_PASSWORD); ?>" <?php echo $check_elev_userandpw; ?>/>
            <?php echo $lang->get('yubiucp_field_flags_userandpw'); ?>
          </label>
        </td>
      </tr>
      <tr>
        <td>
        </td>
        <td>
          <label>
            <input type="checkbox" name="allow_no_yubikey" <?php if ( $yubi_flags & YK_SEC_ALLOW_NO_OTP ) echo 'checked="checked" '; ?>/>
            <?php echo $lang->get('yubiucp_field_allow_plain_login'); ?>
          </label>
          <br />
          <small>
            <?php echo $lang->get('yubiucp_field_allow_plain_login_hint'); ?>
          </small>
        </td>
      </tr>
    </table>
    <table border="0" cellpadding="4" width="100%">
      <tr class="yk_alt1">
        <td colspan="2" style="text-align: center;">
          <input type="submit" name="submit" value="<?php echo $lang->get('etc_save_changes'); ?>" />
        </td>
      </tr>
    </table>
  </div>
  
  <input type="hidden" name="cstok" value="<?php echo $session->csrf_token; ?>" />
  
  </form>
  <?php
  
  return true;
}

function yubikey_inject_html_login()
{
  global $lang;
  ?>
  <tr>
    <td class="row2">
      <?php echo $lang->get('yubiauth_lbl_otp_field'); ?>
    </td>
    <td class="row1" colspan="2">
      <input type="text" size="40" class="yubikey_noscript" name="yubikey_otp" />
    </td>
  </tr>
  <?php
}

function yubikey_inject_registration_form()
{
  global $lang;
  
  $preset_otp = isset($_POST['yubikey_otp']) ? $_POST['yubikey_otp'] : false;
  ?>
  <tr>
    <td class="row1">
      <?php echo $lang->get('yubiucp_reg_field_otp'); ?><br />
      <small><?php
        if ( getConfig('yubikey_reg_require_otp', '0') == '1' )
          echo $lang->get('yubiucp_reg_field_otp_hint_required');
        else
          echo $lang->get('yubiucp_reg_field_otp_hint_optional');
      ?></small>
    </td>
    <td class="row1">
      <?php
      echo generate_yubikey_field('yubikey_otp', $preset_otp);
      ?>
    </td>
    <td class="row1">
    </td>
  </tr>
  <?php
}

function yubikey_register_validate(&$error)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  global $lang;
  
  $otp_required = getConfig('yubikey_reg_require_otp', '0') == '1';
  $have_otp = !empty($_POST['yubikey_otp']);
  if ( $otp_required && !$have_otp )
  {
    $error = $lang->get('yubiucp_reg_err_otp_required');
    return false;
  }
  if ( $have_otp )
  {
    $result = yubikey_validate_otp($_POST['yubikey_otp']);
    if ( !$result['success'] )
    {
      $error = '<b>' . $lang->get('yubiucp_reg_err_otp_invalid') . '</b><br />' . $lang->get("yubiauth_err_{$result['error']}");
      return false;
    }
    // check for double enrollment
    $yubi_uid = substr($_POST['yubikey_otp'], 0, 12);
    // Note on SQL injection: yubikey_validate_otp() has already ensured that this is safe
    $q = $db->sql_query('SELECT 1 FROM ' . table_prefix . "yubikey WHERE yubi_uid = '$yubi_uid';");
    if ( !$q )
      $db->_die();
    if ( $db->numrows() > 0 )
    {
      $error = '<b>' . $lang->get('yubiucp_reg_err_otp_invalid') . '</b><br />' . $lang->get('yubiucp_err_double_enrollment_single');
      return false;
    }
    $db->free_result();
  }
}

function yubikey_register_insert_key($user_id)
{
  global $db, $session, $paths, $template, $plugins; // Common objects
  if ( !empty($_POST['yubikey_otp']) )
  {
    $yubi_uid = $db->escape(substr($_POST['yubikey_otp'], 0, 12));
    $q = $db->sql_query('INSERT INTO ' . table_prefix . "yubikey ( user_id, yubi_uid ) VALUES ( $user_id, '$yubi_uid' );");
    if ( !$q )
      $db->_die();
  }
}
