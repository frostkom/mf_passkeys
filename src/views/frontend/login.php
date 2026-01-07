<?php

echo "<div class='secure-passkey-login-wrapper wp-block-button'>
	<p>".__("...or login safer with...", 'lang_passkeys')."</p>
	<div class='notification errorMessage'><div class='notice notice-error error'><p></p></div></div>
	<div class='notification successMessage'><div class='notice notice-success updated'><p></p></div></div>
	<button class='button wp-block-button__link'>
		<span class='spinnerText'>".__("Logging in via Passkey...", 'lang_passkeys')."</span>
		<span class='buttonText'>".__("Passkey", 'lang_passkeys')."</span>
	</button>
</div>";