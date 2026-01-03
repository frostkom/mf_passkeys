<?php
/**
 * Login Default template
 *
 * @package SecurePasskeys
 */

defined('ABSPATH') || exit;
?>
<div id="secure-passkey-login-wrapper" class="secure-passkey-login-wrapper wp-block-button" style="display: none;">
	<div id="errorMessage" class='notification' style="display: none;"><div class="notice notice-error error"><p></p></div></div>
	<div id="successMessage" class='notification' style="display: none;"><div class="notice notice-success updated"><p></p></div></div>
	<button id="login-via-passkey" class="button button-large login-via-passkey wp-block-button__link">
		<span id="spinnerText" style="display: none;"><?php echo __("Login via Passkey...", 'lang_passkeys') ;?></span>
		<span id="buttonText"><?php echo __("Login via Passkey", 'lang_passkeys') ;?></span>
	</button>
</div>