<?php
/**!info**
{
  "Plugin Name"  : "Yubikey authentication",
  "Plugin URI"   : "http://enanocms.org/plugin/yubikey",
  "Description"  : "Allows authentication to Enano via Yubico's Yubikey, a one-time password device.",
  "Author"       : "Dan Fuhry",
  "Version"      : "1.1.6",
  "Author URI"   : "http://enanocms.org/",
  "Auth plugin"  : true
}
**!*/

// Include files
require( ENANO_ROOT . '/plugins/yubikey/corelib.php' );
require( ENANO_ROOT . '/plugins/yubikey/admincp.php' );

if ( getConfig('yubikey_enable', '1') == '1' )
{
  require( ENANO_ROOT . '/plugins/yubikey/auth.php' );
  require( ENANO_ROOT . '/plugins/yubikey/usercp.php' );
}

// Install schema: MySQL
/**!install dbms="mysql"; **
CREATE TABLE {{TABLE_PREFIX}}yubikey(
  yubi_id int(12) NOT NULL auto_increment,
  user_id mediumint(8) NOT NULL DEFAULT 1,
  yubi_uid char(12) NOT NULL DEFAULT '____________',
  PRIMARY KEY ( yubi_id )
) ENGINE `MyISAM` CHARACTER SET `utf8` COLLATE `utf8_bin`;

ALTER TABLE {{TABLE_PREFIX}}users ADD COLUMN user_yubikey_flags smallint(3) NOT NULL DEFAULT 0;
**!*/

// Install schema: PostgreSQL
/**!install dbms="postgresql"; **
CREATE TABLE {{TABLE_PREFIX}}yubikey(
  yubi_id SERIAL,
  user_id int NOT NULL DEFAULT 1,
  yubi_uid char(12) NOT NULL DEFAULT '____________',
  PRIMARY KEY ( yubi_id )
);

ALTER TABLE {{TABLE_PREFIX}}users ADD COLUMN user_yubikey_flags smallint NOT NULL DEFAULT 0;
**!*/

// Uninstall schema
/**!uninstall**
DROP TABLE {{TABLE_PREFIX}}yubikey;
ALTER TABLE {{TABLE_PREFIX}}users DROP user_yubikey_flags;
**!*/

/**!language**

The following text up to the closing comment tag is JSON language data.
It is not PHP code but your editor or IDE may highlight it as such. This
data is imported when the plugin is loaded for the first time; it provides
the strings displayed by this plugin's interface.

You should copy and paste this block when you create your own plugins so
that these comments and the basic structure of the language data is
preserved. All language data is in the same format as the Enano core
language files in the /language/* directories. See the Enano Localization
Guide and Enano API Documentation for further information on the format of
language files.

The exception in plugin language file format is that multiple languages
may be specified in the language block. This should be done by way of making
the top-level elements each a JSON language object, with elements named
according to the ISO-639-1 language they are representing. The path should be:

  root => language ID => categories array, ( strings object => category \
  objects => strings )

All text leading up to first curly brace is stripped by the parser; using
a code tag makes jEdit and other editors do automatic indentation and
syntax highlighting on the language data. The use of the code tag is not
necessary; it is only included as a tool for development.

<code>
{
  // english
  eng: {
    categories: [ 'meta', 'yubiauth', 'yubiucp', 'yubiacp' ],
    strings: {
      meta: {
        yubiauth: 'Yubikey authentication messages',
        yubiucp: 'Yubikey user CP',
        yubiacp: 'Yubikey admin CP',
      },
      yubiauth: {
        msg_please_touch_key: 'Please touch your Yubikey',
        msg_close_instructions: 'Press <tt>Esc</tt> to cancel',
        msg_invalid_chars: 'OTP contains invalid characters',
        msg_too_long: 'OTP is too long',
        msg_validating_otp: 'Validating OTP...',
        msg_otp_valid: 'OTP validated',
        btn_enter_otp: 'Enter a Yubikey OTP',
        lbl_otp_field: 'Yubikey OTP:',
        
        ctl_btn_change_key: 'Change key',
        ctl_btn_clear: 'Clear',
        ctl_btn_enroll: 'Enroll',
        ctl_status_enrolled_pending: 'Enrolled (pending)',
        ctl_status_empty: 'Not enrolled',
        ctl_status_remove_pending: 'Removed (pending)',
        ctl_status_enrolled: 'Enrolled',
        
        err_invalid_otp: 'Your login was rejected because the Yubikey OTP you entered contains invalid characters.',
        err_invalid_auth_url: 'Login with Yubikey was rejected because the URL to the authentication server is not valid.',
        err_nothing_provided: 'You did not provide a Yubikey OTP or a username. One of these is required for login to work.',
        err_must_have_otp: 'Please provide a Yubikey OTP to log in to this account.',
        err_must_have_username: 'Please provide your username.',
        err_must_have_password: 'Please enter your password in addition to your username and Yubikey.',
        err_key_not_authorized: 'This Yubikey is not authorized on this site.',
        err_otp_invalid_chars: '%this.yubiauth_err_invalid_otp%',
        err_missing_api_key: 'Your OTP could not be validated because no Yubico API key is registered on this site.',
        err_http_response_error: 'Your OTP could not be validated because the Yubico authentication server reported an error.',
        err_malformed_response: 'Your OTP could not be validated because the Yubico authentication server returned an unexpected response.',
        err_timestamp_check_failed: 'Your OTP could not be validated because the timestamp of the response from the Yubico authentication server was out of bounds.',
        err_response_missing_sig: 'Your OTP could not be validated because the Yubico authentication server did not sign its response.',
        err_response_invalid_sig: 'Your OTP could not be validated because the signature of the authentication response was invalid.',
        err_response_missing_status: '%this.yubiauth_err_malformed_response%',
        err_response_ok: 'OTP is OK',
        err_response_bad_otp: 'Authentication failed because the Yubikey OTP is invalid.',
        err_response_replayed_otp: 'Authentication failed because the Yubikey OTP you entered has been used before.',
        err_response_bad_signature: 'Authentication failed because the Yubico authentication server reported an invalid signature.',
        err_response_missing_parameter: 'Authentication failed because of a Dan Fuhry error.',
        err_response_no_such_client: 'Authentication failed because the Yubikey you used is not registered with Yubico.',
        err_response_operation_not_allowed: 'Authentication failed because the Enano server was denied the request to validate the OTP.',
        err_response_backend_error: 'Authentication failed because an unexpected problem happened with the Yubico server.',
        err_response_security_error: 'Authentication failed because the Yubico authentication server reported an unknown security error.',
        
        specialpage_yubikey: 'Yubikey API'
      },
      yubiucp: {
        panel_title: 'Yubikey settings',
        
        field_enable_title: 'Enable Yubikey support on my account:',
        field_enable_hint: 'Disabling support will remove any keys that are enrolled for your account.',
        field_enable: 'Enabled',
        field_keys_title: 'Enrolled Yubikeys:',
        field_keys_hint: 'Enroll a Yubikey to allow it to log into your account.',
        field_keys_maximum: 'You can enroll up to %max% Yubikeys.',
        field_normal_flags: 'When logging in:',
        field_elev_flags: 'When performing sensitive operations:',
        field_flags_keyonly: 'Only require my Yubikey',
        field_flags_username: 'Require a username',
        field_flags_userandpw: 'Require a username and password',
        field_allow_plain_login: 'Allow me to log in without my Yubikey',
        field_allow_plain_login_hint: 'If this option is turned off, you will be unable to access your account if all of your enrolled Yubikeys become lost or broken. However, turning this option off provides greater security.',
        err_double_enrollment: 'One of the Yubikeys you tried to enroll is already enrolled on another account on this website. A single Yubikey can only be associated with one account at a time.',
        err_double_enrollment_single: 'The Yubikey you tried to enroll is already enrolled on another account on this website. A single Yubikey can only be associated with one account at a time.',
        
        reg_field_otp: 'Enroll a <a href="http://www.yubico.com/products/yubikey" onclick="window.open(this.href); return false;">Yubikey</a>:',
        reg_field_otp_hint_optional: 'If you have a Yubikey, you can authorize it for use in your new account here.',
        reg_field_otp_hint_required: 'Please enroll a Yubikey here to create an account. This is a required step.',
        reg_err_otp_required: 'Please enroll a Yubikey to register on this site.',
        reg_err_otp_invalid: 'Your Yubikey OTP failed to validate.'
      },
      yubiacp: {
        th: 'Yubikey authentication',
        field_enable_title: 'Yubikey support:',
        field_enable: 'Enable Yubikey authentication',
        field_api_key: 'Yubico API key:',
        field_api_key_id: 'Yubico numeric ID:',
        field_auth_server: 'Authentication server URL:',
        field_enroll_limit: 'Number of enrolled keys permitted per account:',
        field_reg_require_otp_title: 'Yubikey required for registration:',
        field_reg_require_otp_hint: 'If this is enabled, users will be asked to enroll a Yubikey during registration. The enrolled Yubikey will be authorized for the new account.',
        field_reg_require_otp: 'Require Yubikey during registration',
        
        err_invalid_auth_server: 'The URL to the Yubikey authentication server that you entered is invalid.'
      }
    }
  }
}
</code>
**!*/

