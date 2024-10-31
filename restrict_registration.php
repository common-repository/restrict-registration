<?php
/*
Plugin Name: Restrict Registration
Plugin URI: http://davidbaumgold.com/projects/restrict-registration/
Description: Control who can register on your blog using blacklists and whitelists. Choose between three different matching styles: exact, asterisk wildcard, and regular expressions. Simple and powerful security for your blog!
Version: 2.3
Author: David Baumgold
Author URI: http://davidbaumgold.com

This plugin uses blacklists and whitelists to control which usernames and email addresses can register for your blog. Any registration that matches an entry on the blacklist but not on the whitelist results in an error and a denial message. Set your restriction terms under Users -> Restrict Registration.

This plugin is inspired by WP-Deadbolt by whoo (http://www.village-idiot.org/archives/2007/04/24/wp-deadbolt-3/), but has been completely rewritten, and extended to cover usernames and multiple matching types.

*/

global $wpdb;

# DEFINITIONS
define("RR_DB_NAME", $wpdb->prefix."restrict_registration");
define("RR_EXP_MATCH", "restrict_registration_expression_type");
define("RR_USER_MESSAGE", "restrict_registration_user_denial_message");
define("RR_EMAIL_MESSAGE", "restrict_registration_email_denial_message");

add_action('register_post', 'check_restrictions', 10, 3);
if(!function_exists('check_restrictions')) :
function check_restrictions($user_login, $user_email, $errors) {
# The function passes in $user_login, $user_email, and $errors
	   
	# what matching style are we using?
	# make a test function called rr_match, which is different
	# depending on the matching style.
	#
	# If the $match_array is empty, return false: there's nothing
	# to match, so you didn't match anything. If 
	switch(get_option(RR_EXP_MATCH)) {
	   case 0:     # literal match
	      function rr_match($value, $match_array) { 
	         if($match_array) {
	            foreach($match_array as $expr) {
	               if (strcasecmp($expr, $value) == 0) { # strings are equal
	                  return true;
	               }
	            }
	         }
	         # $match_array is empty: no match
	         return false;
	      }
	      break;
	   case 1:     # wildcard match
         function rr_match($value, $match_array) {
            if($match_array) { 
	            foreach($match_array as $expr) {
	               # clone for safety
	               $clone = $value;
	               
                  # divide string into parts such that each part
                  # begins with a wildcard
                  $wc_parts = array();
                  preg_match_all('/.[^*]*/i', $expr, $wc_parts);
                  # use for instead of foreach so we keep track
                  # of how far along we are
                  for($i = 0; $i < count($wc_parts[0]); $i++) {
                     $bit = $wc_parts[0][$i];
#                     var_dump($bit);
                     
                     if($bit == '*') {
                        # if bit equals exactly *, it matches EVERYTHING,
                        # which means this is an automatic match
#                        echo "return 1".PHP_EOL;
                        return true;
                     }
                     if(substr($bit, 0, 1) == '*') {
                        # if the FIRST char of bit is a wildcard,
                        # but there is more in bit, we match the
                        # rest against the value. Ignore the first
                        # in clone as well, to account for wildcard.
                        $str_match = stristr(substr($clone, 1), substr($bit, 1));
                        if($str_match === false) {
                           # bit did not match, so we're done with 
                           # this expression. Break the loop that has multiple
                           # match bits
#                           echo "break 1".PHP_EOL;
                           break;
                        } else {
                           if ($i == count($wc_parts)) {
                              # if this is the last bit in the expr, it's a match!
#                              echo "return 2".PHP_EOL;
                              return true;
                           } else {
                              # strip out the contents of bit from str_match, and stuff
                              # the rest into clone, so the next iteration compares
                              # against the right info
                              $clone = substr($str_match, strlen($bit));
                              # if this is the last bit, and there's nothing left in $clone,
                              # it's a match!
                              if($i == count($wc_parts[0])-1 && $clone == ''){
#                                 echo "return 3".PHP_EOL;
                                 return true;
                              }
#                              echo "continue 1".PHP_EOL;
                              continue;
                           }
                        }
                     } else {
                        # if the first char of bit is NOT a wildcard,
                        # bit is located before the first wildcard in expr.
                        if(strpos($expr, '*') === false) {
                           # there is NO wildcard: this is a literal match.
                           if(strcasecmp($bit, $clone) === 0) {
                              # match!
#                              echo 'return 4'.PHP_EOL;
                              return true;
                           }
                        }
                        if($bit == substr($clone, 0, strlen($bit))) {
                           # if bit matches, chop that bit off clone and move along
                           $clone = substr($clone, strlen($bit));
#                           echo "continue 2".PHP_EOL;
                           continue;
                        } else {
                           # if not, we're done with this expression.
                           # Break, and go on to the next.
 #                          echo "break 2".PHP_EOL;
                           break;
                        }
                     }
                     # end of checking the bits of the specific expr
                  }
                  # end of checking expr
               }
               # if we've gotten to this point, none of the exprs match, so we
               # can confidently return false.
#               echo "return 5".PHP_EOL;
               return false;
            }
            # if we get here, that means that match_array was empty, and there were
            # never any exprs in the first place. Also return false.
#            echo "return 6".PHP_EOL;
            return false;
         }
         break;                  
	   case 2:     # regex match
	      function rr_match($value, $match_array) {
	         if($match_array) {
	            foreach($match_array as $expr) {
	               if(preg_match('/'.$expr.'/i', $value)) {
	                  return true;
	               }
	            }
	         }
	         # $match_array is empty: no match
	         return false;
	      }
	      break;
	   default:
	      error_log("Error: Unknown matching style for restrict registration plugin (incorrect value in WordPress option ".RR_EXP_MATCH.")");
	}
	
	#import database
	global $wpdb;
   # grab blacklists from db
	$user_blacklist = $wpdb->get_col('
	   SELECT expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 0
	   AND allow = FALSE;
	');
	$email_blacklist = $wpdb->get_col('
	   SELECT expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 1
	   AND allow = FALSE;
	');
	
	# allowed by default
	$allowed = true;
	
	# Check username first
	# If rr_match returns true, allowed should be false
	$allowed = !rr_match($user_login, $user_blacklist);
	if(!$allowed){
	   $user_whitelist = $wpdb->get_col('
   	   SELECT expression
   	   FROM '.RR_DB_NAME.'
   	   WHERE user_attribute = 0
   	   AND allow = TRUE;
   	');
   	
   	# this time, if rr_match returns true, allowed should be true
	   $allowed = rr_match($user_login, $user_whitelist);
	}
	
	# Now, if we're still not allowed, throw an error
	if(!$allowed) {
		# unfortunately, we cannot modify the $errors within this action: neither passing
		# by reference nor using the global version works. However, we can use a filter,
		# which takes $errors as an arg and asks for $errors as a return value. Therefore,
		# we will register a filter function to add the user error for us.
		add_filter('registration_errors', add_user_error_via_filter);
	}
	
	# Next, test email
	$allowed = !rr_match($user_email, $email_blacklist);
	if(!$allowed){
	   $email_whitelist = $wpdb->get_col('
   	   SELECT expression
   	   FROM '.RR_DB_NAME.'
   	   WHERE user_attribute = 1
   	   AND allow = TRUE;
   	');
	   $allowed = rr_match($user_email, $email_whitelist);
	}
	
	# Now, if we're still not allowed, throw an error
	if(!$allowed) {
		# same deal with email error
		add_filter('registration_errors', add_email_error_via_filter);
	}
}
endif;

if(!function_exists('add_user_error_via_filter')) :
function add_user_error_via_filter($errors) {
	$errors->add('unauthorized_registration_user', '<strong>'.strtoupper(__('error')).':</strong> ' . get_option(RR_USER_MESSAGE));
	# remove this so it doesn't run every time
	remove_filter('registration_errors', add_user_error_via_filter);
	# and return our modified $errors
	return $errors;
}
endif;

if(!function_exists('add_email_error_via_filter')) :
function add_email_error_via_filter($errors) {
	$errors->add('unauthorized_registration_email', '<strong>'.strtoupper(__('error')).':</strong> ' . get_option(RR_EMAIL_MESSAGE));
	# remove this so it doesn't run every time
	remove_filter('registration_errors', add_email_error_via_filter);
	# and return our modified $errors
	return $errors;
}
endif;

# Activation function
register_activation_hook( __FILE__, 'restrict_registration_activate');
if(!function_exists('restrict_registration_activate')) :
function restrict_registration_activate() {
	# create restriction database
	global $wpdb;
	$wpdb->query("
	CREATE TABLE IF NOT EXISTS ".RR_DB_NAME." (
	   id int(11) unsigned NOT NULL AUTO_INCREMENT,
	   expression varchar(64) NOT NULL,
	   user_attribute int unsigned NOT NULL DEFAULT 1,
	   allow bool NOT NULL DEFAULT FALSE,
	   PRIMARY KEY (id)
	);");
	# user_attribute: 0 is username, 1 is email
	
	# Default settings, user can change these via the admin area
	if(get_option(RR_EXP_MATCH) === False) {
	   add_option(RR_EXP_MATCH, 1); 
	   # 0 = literal
	   # 1 = asterisk wildcard
	   # 2 = regular expressions
	}
	if(get_option(RR_USER_MESSAGE) === False) {
		add_option(RR_USER_MESSAGE, __('That username is not allowed to register for this blog.'));	
	}
	if(get_option(RR_EMAIL_MESSAGE) === False) {
		add_option(RR_EMAIL_MESSAGE, __('That email address is not allowed to register for this blog.'));	
	}
}
endif;

#Deactivation function
register_deactivation_hook( __FILE__, 'restrict_registration_deactivate');
if(!function_exists('restrict_registration_deactivate')) :
function restrict_registration_deactivate() {
	remove_action('register_post', 'check_restrictions', 10, 3);
	# remove stored data
	global $wpdb;
	$wpdb->query('
	   DROP TABLE IF EXISTS '.RR_DB_NAME.';
	');
	delete_option(RR_EXP_MATCH);
	delete_option(RR_USER_MESSAGE);
	delete_option(RR_EMAIL_MESSAGE);
}	
endif;
		
# Admin Options page

add_action('admin_menu', 'restrict_registration_options_page');
function restrict_registration_options_page() {
	if (function_exists('add_submenu_page')) {
		add_submenu_page('users.php', 'Restrict Registration', 'Restrict Registration', '8', __FILE__, 'restrict_registration_display_options_page');
	}
}

function restrict_registration_display_options_page() {
   global $wpdb;
   $wpdb->show_errors();
   if( $_POST ){
      foreach($_POST as $key => $value) {
         $parts = explode('-', $key);
         if(count($parts) == 3) {
            # this is an expression field
            switch($parts[0]) {
               case "user":
                  $user_attribute = 0;
                  break;
               case "email":
                  $user_attribute = 1;
                  break;
            }
            switch($parts[1]) {
               case "black":
                  $allow = 0;
                  break;
               case "white":
                  $allow = 1;
                  break;
            }
            if(strpos($parts[2], "new") !== False) {
               # this is a new entry
               if($value != '') {
                  # we don't care about new fields with no content
                  $wpdb->query( stripslashes( $wpdb->prepare('
                     INSERT INTO '.RR_DB_NAME.'
                     (expression, user_attribute, allow)
                     VALUES ( %s, %d, %d )',
                     $value, $user_attribute, $allow ) ) );                  
               }
            } else {
               # this is updating an existing entry
               if($value == '') {
                  # delete entry
                  $wpdb->query( stripslashes( $wpdb->prepare('
                     DELETE FROM '.RR_DB_NAME.'
                     WHERE id =  %d',
                     $parts[2] ) ) );
               } else {
                  # update entry
                  $wpdb->query( stripslashes( $wpdb->prepare('
                     UPDATE '.RR_DB_NAME.'
                     SET expression = %s
                     WHERE id = %d',
                     $value, $parts[2] ) ) );
               }
            }
      } else {
         if($key != 'submit') {
            # this is an option
            update_option($key, $value);
         }
      }
   }
      # tell the user that their options have been saved
      echo '<div class="updated"><p><strong>'.__('Options saved.').'</strong></p></div>';
   }
   
   # grab lists from db
	$user_blacklist = $wpdb->get_results('
	   SELECT id, expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 0
	   AND allow = FALSE
	   ORDER BY id;
	', ARRAY_A);
	$user_whitelist = $wpdb->get_results('
	   SELECT id, expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 0
	   AND allow = TRUE
	   ORDER BY id;
	', ARRAY_A);
	$email_blacklist = $wpdb->get_results('
	   SELECT id, expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 1
	   AND allow = FALSE
	   ORDER BY id;
	', ARRAY_A);
	$email_whitelist = $wpdb->get_results('
	   SELECT id, expression
	   FROM '.RR_DB_NAME.'
	   WHERE user_attribute = 1
	   AND allow = TRUE
	   ORDER BY id;
	', ARRAY_A);
    # Now display the editing screen
?>
<div class="wrap">
	<h2><?php _e('Restrict User Registration') ?></h2>
	<form id="restrict-registration" method="post" action="<?php echo str_replace( '%7E', '~', $_SERVER['REQUEST_URI']); ?>"> 
		<table class="form-table">
		   <thead>
		      <tr>
		         <th></th>
		         <th scope="col"><?php _e('Blacklist') ?></th>
		         <th scope="col"><?php _e('Whitelist') ?></th>
		      </tr>
		   </thead>
			<tbody>
				<tr>
					<th scope="row"><?php _e('Username') ?></th>
					<td valign="top">
					   <ul id="user-black">
<?php
   if($user_blacklist) {
      foreach($user_blacklist as $row) {
         echo '<li><input type="text" name="user-black-'.$row[id].'" id="user-black-'.$row[id].'" value="'.$row[expression].'" /></li>'.PHP_EOL;
      }
   }
   echo '<li><input type="text" name="user-black-new" id="user-black-new" value="" /></li>'.PHP_EOL;
?>
					   </ul>
					   <button type="button" value="1"><?php _e('Add'); ?></button>
					</td>
					<td valign="top">
					   <ul id="user-white">
<?php
   if($user_whitelist) {
      foreach($user_whitelist as $row) {
         echo '<li><input type="text" name="user-white-'.$row[id].'" id="user-white-'.$row[id].'" value="'.$row[expression].'" /></li>'.PHP_EOL;
      }
   }
   echo '<li><input type="text" name="user-white-new" id="user-white-new" value="" /></li>'.PHP_EOL;
?>
                  </ul>
                  <button type="button" value="1"><?php _e('Add'); ?></button>
               </td>
				</tr>
				<tr>
					<th scope="row"><?php _e('Email') ?></th>
					<td valign="top">
					   <ul id="email-black">
<?php
   if($email_blacklist) {
      foreach($email_blacklist as $row) {
         echo '<li><input type="text" name="email-black-'.$row[id].'" id="email-black-'.$row[id].'" value="'.$row[expression].'" /></li>'.PHP_EOL;
      }
   }
   echo '<li><input type="text" name="email-black-new" id="email-black-new" value="" /></li>'.PHP_EOL;
?>				 
					   </ul>
					   <button type="button" value="1"><?php _e('Add'); ?></button>
					</td>
					<td valign="top">
					   <ul id="email-white">
<?php
   if($email_whitelist) {
      foreach($email_whitelist as $row) {
         echo '<li><input type="text" name="email-white-'.$row[id].'" id="email-white-'.$row[id].'" value="'.$row[expression].'" /></li>'.PHP_EOL;
      }
   }
   echo '<li><input type="text" name="email-white-new" id="email-white-new" value="" /></li>'.PHP_EOL;
?>
					   </ul>
					   <button type="button" value="1"><?php _e('Add'); ?></button>
					</td>
				</tr>
			</tbody>
		</table>
		<h3><?php _e('Options'); ?></h3>
		<table class="form-table">
		   <tbody>
		      <tr>
		         <th scope="row"><?php _e('Matching type'); ?></th>
		         <td>
		            <ul>   
<?php
$matching = get_option(RR_EXP_MATCH);
$checked = 'checked="checked"';	         
?>
		               <li>
		                  <input type="radio" name="<?php echo RR_EXP_MATCH ?>" value="0" id="match_literal" <?php if($matching==0){echo $checked;}?> />
		                  <label for="match_literal"><?php _e('Exact') ?> (<?php _e('Literal') ?>)</label>
		               </li>
		               <li>
		                  <input type="radio" name="<?php echo RR_EXP_MATCH ?>" value="1" id="match_asterisk" <?php if($matching==1){echo $checked;}?> />
		                  <label for="match_asterisk"><?php _e('Asterisk Wildcards') ?></label>
		               </li>
		               <li>
		                  <input type="radio" name="<?php echo RR_EXP_MATCH ?>" value="2" id="match_regex" <?php if($matching==2){echo $checked;}?> />
		                  <label for="match_regex"><?php _e('Regular Expressions') ?></label> (<a href="http://php.net/manual/en/book.pcre.php">details</a>)
		               </li>
		            </ul>
		         </td>
		      </tr>
				<tr>
					<th scope="row"><label for="<?php echo RR_USER_MESSAGE ?>"><?php _e('User denial message'); ?></label></th>
					<td><input type="text" name="<?php echo RR_USER_MESSAGE; ?>" id="<?php echo RR_USER_MESSAGE; ?>" value="<?php echo get_option(RR_USER_MESSAGE); ?>" style="width: 100%;" /></td>
				</tr>
				<tr>
					<th scope="row"><label for="<?php echo RR_EMAIL_MESSAGE ?>"><?php _e('Email denial message'); ?></label></th>
					<td><input type="text" name="<?php echo RR_EMAIL_MESSAGE; ?>" id="<?php echo RR_EMAIL_MESSAGE; ?>" value="<?php echo get_option(RR_EMAIL_MESSAGE); ?>" style="width: 100%;" /></td>
				</tr>
			</tbody>
		</table>

		<div class="submit">
			<input type="submit" value="<?php _e('Update'); ?>" name="submit" />
		</div>
	</form>
	<script type="text/javascript" charset="utf-8">
	  jQuery(document).ready(function($){
	     $('#restrict-registration button').click(function () {
	        var ul = $(this).prev();
	        var name = ul.attr('id') + '-new' + $(this).val();
	        ul.append('<li><input type="text" name="' + name + '" id="' + name + '" value="" /></li>');
	        $(this).val( parseInt($(this).val()) + 1);
	     });
	  });
	</script>
</div>

<?php
}
?>
