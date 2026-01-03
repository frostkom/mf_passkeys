<?php
/*
Plugin Name: MF Passkeys
Plugin URI: 
Description: Enables passwordless authentication using WebAuthn
Version: 1.3.30
Licence: GPLv2 or later
Author: Martin Fors
Author URI: https://martinfors.se
Text Domain: lang_passkeys
Domain Path: /lang/

Credit URI: https://wordpress.org/plugins/secure-passkeys/
*/

//defined('ABSPATH') || exit;

define('SECURE_PASSKEYS_PLUGIN_DIR', __DIR__);
define('SECURE_PASSKEYS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SECURE_PASSKEYS_PLUGIN_BASENAME', 'secure-passkeys');
define('SECURE_PASSKEYS_NONCE', 'secure-passkeys-nonce');

if(!function_exists('is_plugin_active') || function_exists('is_plugin_active') && is_plugin_active("mf_base/index.php"))
{
	include_once("include/classes.php");

	$obj_passkeys = new mf_passkeys();

	add_action('init', array($obj_passkeys, 'init'));

	add_action('cron_base', 'activate_passkeys', 1);
	add_action('cron_base', array($obj_passkeys, 'cron_base'), mt_rand(1, 10));

	if(is_admin())
	{
		register_activation_hook(__FILE__, 'activate_passkeys');
		register_uninstall_hook(__FILE__, 'uninstall_passkeys');

		add_action('deleted_user', [$obj_passkeys, 'deleted_user']);
		add_filter('manage_users_columns', [$obj_passkeys, 'manage_users_columns']);
		add_action('manage_users_custom_column', [$obj_passkeys, 'manage_users_custom_column'], 10, 3);
		add_action('admin_notices', [$obj_passkeys, 'admin_notices']);

		add_action('show_user_profile', [$obj_passkeys, 'edit_user_profile'], 1);
		add_action('edit_user_profile', [$obj_passkeys, 'edit_user_profile'], 1);

		add_action('admin_enqueue_scripts', [$obj_passkeys, 'enqueue_scripts'], 10);
		add_action('admin_enqueue_scripts', [$obj_passkeys, 'enqueue_profile_passkey_vue_script'], 10);
	}

	else
	{
		add_action('login_form', [$obj_passkeys, 'login_form']);
	}

	if(wp_doing_ajax())
	{
		add_action('wp_ajax_secure_passkeys_adminarea_delete_passkey', [$obj_passkeys, 'delete_passkey']);
		add_action('wp_ajax_secure_passkeys_adminarea_get_profile_registered_passkeys_list', [$obj_passkeys, 'get_profile_registered_passkeys_list']);

		add_action('wp_ajax_nopriv_secure_passkeys_frontend_get_login_options', [$obj_passkeys, 'get_ajax_login_options'], 100);
		add_action('wp_ajax_nopriv_secure_passkeys_frontend_login', [$obj_passkeys, 'login'], 100);
		add_action('wp_ajax_secure_passkeys_frontend_get_registered_passkeys_list', [$obj_passkeys, 'get_registered_passkeys_list'], 100);
		add_action('wp_ajax_secure_passkeys_frontend_get_register_options', [$obj_passkeys, 'get_register_options'], 100);
		add_action('wp_ajax_secure_passkeys_frontend_register_passkey', [$obj_passkeys, 'register_passkey'], 100);
		add_action('wp_ajax_secure_passkeys_frontend_remove_passkey', [$obj_passkeys, 'remove_passkey'], 100);
	}

	add_filter('filter_login_redirect', array($obj_passkeys, 'filter_login_redirect'), 11, 2);

	function activate_passkeys()
	{
		global $wpdb, $obj_passkeys;

		if(!isset($obj_passkeys))
		{
			$obj_passkeys = new mf_passkeys();
		}

		$default_charset = (DB_CHARSET != '' ? DB_CHARSET : 'utf8');

		$arr_add_column = $arr_update_column = $arr_add_index = [];

		$wpdb->query("CREATE TABLE IF NOT EXISTS ".$wpdb->base_prefix."secure_passkeys_challenges (
			id BIGINT(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id INT(11) DEFAULT NULL,
			blog_id INT(11) NOT NULL,
			challenge_type ENUM('authentication', 'registration') NOT NULL,
			challenge VARCHAR(255) NOT NULL,
			fingerprint VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			expired_at TIMESTAMP NULL DEFAULT NULL,
			used_at TIMESTAMP NULL DEFAULT NULL,
			created_at TIMESTAMP NULL DEFAULT NULL,
			updated_at TIMESTAMP NULL DEFAULT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY challenge (challenge),
			KEY user_id (user_id)
		) DEFAULT CHARSET=".$default_charset);

		$arr_add_column[$wpdb->base_prefix.""] = array(
			//'' => "ALTER TABLE [table] ADD [column] ENUM('no', 'yes') NOT NULL DEFAULT 'no' AFTER ",
		);

		$arr_update_column[$wpdb->base_prefix.""] = array(
			//'' => "ALTER TABLE [table] CHANGE [column] [column] VARCHAR(129) DEFAULT NULL",
		);

		$wpdb->query("CREATE TABLE IF NOT EXISTS ".$wpdb->base_prefix."secure_passkeys_logs (
			id BIGINT(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id INT(11) NOT NULL,
			blog_id INT(11) NOT NULL,
			admin_id INT(11) DEFAULT NULL,
			webauthn_id INT(11) DEFAULT NULL,
			security_key_name VARCHAR(255) DEFAULT NULL,
			aaguid CHAR(36) DEFAULT NULL,
			log_type VARCHAR(255) NOT NULL,
			ip_address VARCHAR(45) NOT NULL,
			created_at TIMESTAMP NULL DEFAULT NULL,
			updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY user_id (user_id)
		) DEFAULT CHARSET=".$default_charset);

		$wpdb->query("CREATE TABLE IF NOT EXISTS ".$wpdb->base_prefix."secure_passkeys_webauthns (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			user_id INT(11) NOT NULL,
			blog_id INT(11) NOT NULL,
			credential_id VARCHAR(255) NOT NULL,
			is_active TINYINT(1) NOT NULL DEFAULT '1',
			security_key_name VARCHAR(255) NOT NULL,
			public_key TEXT NOT NULL,
			aaguid CHAR(36) NOT NULL,
			last_used_at DATETIME DEFAULT NULL,
			created_at TIMESTAMP NULL DEFAULT NULL,
			updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) DEFAULT CHARSET=".$default_charset);

		update_columns($arr_update_column);
		add_columns($arr_add_column);
		add_index($arr_add_index);
	}

	function uninstall_passkeys()
	{
		include_once("include/classes.php");

		$obj_passkeys = new mf_passkeys();

		mf_uninstall_plugin(array(
			//'options' => array(''),
			'tables' => array('secure_passkeys_challenges', 'secure_passkeys_logs', 'secure_passkeys_webauthns'),
		));
	}
}