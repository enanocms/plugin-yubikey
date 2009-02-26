// sample OTP:
// ttttvvvvvvcurikvhjcvnlnbecbkubjvuittbifhndhn
// charset: cbdefghijklnrtuv

var yk_interval = false;

var YK_SEC_NORMAL_USERNAME = 1;
var YK_SEC_NORMAL_PASSWORD = 2;
var YK_SEC_ELEV_USERNAME = 4;
var YK_SEC_ELEV_PASSWORD = 8;

var yubikey_otp_current = false;

function yk_mb_init(fieldid, statid)
{
  load_component(['messagebox', 'fadefilter', 'flyin', 'jquery', 'jquery-ui', 'l10n']);
  var mp = miniPrompt(yk_mb_construct);
  if ( typeof(fieldid) == 'function' )
  {
    var input = mp.getElementsByTagName('input')[0];
    input.submit_func = fieldid;
  }
  else if ( fieldid && statid )
  {
    var input = mp.getElementsByTagName('input')[0];
    input.yk_field_id = fieldid;
    input.yk_status_id = statid;
  }
}

function yk_mb_construct(mp)
{
  mp.innerHTML = '';
  mp.style.textAlign = 'center';
  mp.innerHTML = '<h3>' + $lang.get('yubiauth_msg_please_touch_key') + '</h3>';
  var ta = document.createElement('input');
  ta.submitted = false;
  $(ta)
    .css('background-color', 'transparent')
    .css('border-width', '0px')
    .css('color', '#fff')
    .css('font-size', '1px')
    .css('padding', '0')
    .attr('size', '1')
    .keyup(function(e)
      {
        if ( e.keyCode == 27 )
        {
          window.clearInterval(yk_interval);
          miniPromptDestroy(this);
        }
        else if ( this.value.length == 44 && !this.submitted )
        {
          this.submitted = true;
          yk_handle_submit(this);
        }
        e.preventDefault();
        e.stopPropagation();
      });
  mp.appendChild(ta);
  setTimeout(function()
    {
      window.yk_interval = setInterval(function()
        {
          ta.focus();
        }, 50);
    }, 750);
  var info = document.createElement('p');
  info.innerHTML = $lang.get('yubiauth_msg_close_instructions');
  mp.appendChild(info);
}

function yk_handle_submit(ta)
{
  if ( !ta.value.match(/^[cbdefghijklnrtuv]{44}$/) )
  {
    setTimeout(function()
      {
        yk_mb_construct(ta.parentNode);
      }, 1000);
    ta.previousSibling.innerHTML = $lang.get('yubiauth_msg_invalid_chars');
    return false;
  }
  
  window.clearInterval(yk_interval);
  
  if ( ta.yk_field_id && ta.yk_status_id )
  {
    var field = document.getElementById(ta.yk_field_id);
    var status = document.getElementById(ta.yk_status_id);
    if ( $(status).hasClass('empty') || $(status).hasClass('rmpending') )
    {
      $(status).next('a')
        .text($lang.get('yubiauth_ctl_btn_change_key'))
        .addClass('abutton_green')
        .after(' <a class="abutton abutton_red yubikey_enroll" href="#yk_clear" onclick="yk_clear(\'' + ta.yk_field_id + '\', \'' + ta.yk_status_id + '\'); return false;">'
               + $lang.get('yubiauth_ctl_btn_clear') +
               '</a>');
    }
    $(status).removeClass('empty').removeClass('enrolled').removeClass('rmpending').addClass('savepending').html($lang.get('yubiauth_ctl_status_enrolled_pending'));
    field.value = ta.value;
    miniPromptDestroy(ta);
    return true;
  }
  else if ( ta.submit_func )
  {
    ta.submit_func(ta);
  }
  else
  {
    miniPromptDestroy(ta);
  }
}

function yk_login_validate_reqs(ta)
{
  ta.parentNode.removeChild(ta.nextSibling);
  yubikey_otp_current = ta.value;
  
  ta.previousSibling.innerHTML = $lang.get('yubiauth_msg_validating_otp');
  
  ajaxPost(makeUrlNS('Special', 'Yubikey'), 'get_flags=' + ta.value.substr(0, 12), function(ajax)
    {
      if ( ajax.readyState == 4 && ajax.status == 200 )
      {
        miniPromptDestroy(ta);
        if ( !check_json_response(ajax.responseText) )
        {
          handle_invalid_json(ajax.responseText);
          return false;
        }
        ta.previousSibling.innerHTML = $lang.get('yubiauth_msg_otp_valid');
        var response = parseJSON(ajax.responseText);
        if ( response.mode == 'error' )
        {
          alert('Yubikey server-side processing error: \n' + response.error);
          return false;
        }
        if ( logindata )
        {
          if ( logindata.mb_object )
          {
            // login window is open
            if ( user_level == USER_LEVEL_GUEST )
            {
              var show_username = response.flags & YK_SEC_NORMAL_USERNAME;
              var show_password = response.flags & YK_SEC_NORMAL_PASSWORD;
            }
            else
            {
              var show_username = response.flags & YK_SEC_ELEV_USERNAME;
              var show_password = response.flags & YK_SEC_ELEV_PASSWORD;
            }
            if ( !show_username )
              $('#ajax_login_field_username').parent('td').hide().prev().hide();
            if ( !show_password )
              $('#ajax_login_field_password').parent('td').hide().prev().hide();
            
            var can_submit = true;
            if ( show_username && !$('#ajax_login_field_username').attr('value') )
            {
              $('#ajax_login_field_password').focus();
              can_submit = false;
            }
            if ( show_password && !$('#ajax_login_field_password').attr('value') )
            {
              if ( can_submit )
              {
                $('#ajax_login_field_password').focus();
              }
              can_submit = false;
            }
            
            if ( can_submit )
            {
              $('#messageBoxButtons input:button:first').click();
            }
          }
        }
      }
    });
}

function yk_clear(field_id, status_id)
{
  var field = document.getElementById(field_id);
  var status = document.getElementById(status_id);
  
  var was_pending = $(field).hasClass('wasempty');
  
  $(field).attr('value', '');
  $(status)
    .removeClass('savepending')
    .removeClass('enrolled')
    .addClass( was_pending ? 'empty' : 'rmpending' )
    .text( was_pending ? $lang.get('yubiauth_ctl_status_empty') : $lang.get('yubiauth_ctl_status_remove_pending') )
    .next('a')
      .text($lang.get('yubiauth_ctl_btn_enroll'))
      .removeClass('abutton_green')
    .next('a')
      .remove();
}

addOnloadHook(function()
  {
    attachHook('login_build_form', 'yk_login_dlg_hook(table);');
    attachHook('login_build_userinfo', 'if ( window.yubikey_otp_current ) userinfo.yubikey_otp = window.yubikey_otp_current;');
    load_component(['expander', 'jquery', 'jquery-ui']);
  });

function yk_login_dlg_hook(table)
{
  window.yubikey_otp_current = false;
  var tr = document.createElement('tr');
  var td = document.createElement('td');
  $(td)
    .attr('colspan', '2')
    .css('text-align', 'center')
    .css('font-size', 'smaller')
    .css('font-weight', 'bold')
    .html('<a href="#" onclick="yk_mb_init(yk_login_validate_reqs); return false;" style="color: #6fa202">' + $lang.get('yubiauth_btn_enter_otp') + '</a>');
  $('a', td).blur(function(e)
    {
      $('#messageBoxButtons input:button:first').focus();
      $('#ajax_login_field_captcha').focus();
    });
  tr.appendChild(td);
  table.appendChild(tr);
}
