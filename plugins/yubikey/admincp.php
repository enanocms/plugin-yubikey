<?php

$plugins->attachHook('acp_general_users', 'yubikey_admin_cp_ui();');
$plugins->attachHook('acp_general_save', 'yubikey_admin_cp_save();');

function yubikey_admin_cp_ui()
{
  global $lang;
  ?>
    <tr>
      <th colspan="2" class="subhead">
        <?php echo $lang->get('yubiacp_th'); ?>
      </th>
    </tr>
    
    <tr>
      <td class="row1">
        <?php echo $lang->get('yubiacp_field_enable_title'); ?>
      </td>
      <td class="row1">
        <label>
          <input type="checkbox" name="yubikey_enable" <?php if ( getConfig('yubikey_enable', '1') == '1' ) echo 'checked="checked" '; ?>/>
          <?php echo $lang->get('yubiacp_field_enable'); ?>
        </label>
      </td>
    </tr>
    
    <tr>
      <td class="row2">
        <?php echo $lang->get('yubiacp_field_api_key'); ?>
      </td>
      <td class="row2">
        <input type="text" name="yubikey_api_key" value="<?php echo htmlspecialchars(getConfig('yubikey_api_key', '')); ?>" size="30" />
      </td>
    </tr>
    
    <tr>
      <td class="row1">
        <?php echo $lang->get('yubiacp_field_api_key_id'); ?>
      </td>
      <td class="row1">
        <input type="text" name="yubikey_api_key_id" value="<?php echo strval(intval(getConfig('yubikey_api_key_id', ''))); ?>" size="5" />
      </td>
    </tr>
    
    <tr>
      <td class="row2">
        <?php echo $lang->get('yubiacp_field_auth_server'); ?>
      </td>
      <td class="row2">
        <input type="text" name="yubikey_auth_server" value="<?php echo htmlspecialchars(getConfig('yubikey_auth_server', YK_DEFAULT_VERIFY_URL)); ?>" size="30" />
      </td>
    </tr>
    
    <tr>
      <td class="row1">
        <?php echo $lang->get('yubiacp_field_enroll_limit'); ?>
      </td>
      <td class="row1">
        <input type="text" name="yubikey_enroll_limit" value="<?php echo strval(intval(getConfig('yubikey_enroll_limit', '3'))); ?>" size="5" />
      </td>
    </tr>
    
    <tr>
      <td class="row2">
        <?php echo $lang->get('yubiacp_field_reg_require_otp_title'); ?><br />
        <small><?php echo $lang->get('yubiacp_field_reg_require_otp_hint'); ?></small>
      </td>
      <td class="row2">
        <label>
          <input type="checkbox" name="yubikey_reg_require_otp" <?php if ( getConfig('yubikey_reg_require_otp', '0') == '1' ) echo 'checked="checked" '; ?>/>
          <?php echo $lang->get('yubiacp_field_reg_require_otp'); ?>
        </label>
      </td>
    </tr>
    
  <?php
}

function yubikey_admin_cp_save()
{
  global $lang;
  
  // yubikey_enable, yubikey_api_key, yubikey_api_key_id, yubikey_auth_server, yubikey_enroll_limit
  setConfig('yubikey_enable', isset($_POST['yubikey_enable']) ? '1' : '0');
  setConfig('yubikey_api_key', $_POST['yubikey_api_key']);
  setConfig('yubikey_api_key_id', intval($_POST['yubikey_api_key_id']));
  setConfig('yubikey_enroll_limit', intval($_POST['yubikey_enroll_limit']));
  setConfig('yubikey_reg_require_otp', isset($_POST['yubikey_reg_require_otp']) ? '1' : '0');
  
  if ( preg_match('#^(?:https?://)?(\[?[a-z0-9-:]+(?:\.[a-z0-9-:]+\]?)*)(/.*)$#', $_POST['yubikey_auth_server']) )
    setConfig('yubikey_auth_server', $_POST['yubikey_auth_server']);
  else
    echo '<div class="error-box">' . $lang->get('yubiacp_err_invalid_auth_server') . '</div>';
}

