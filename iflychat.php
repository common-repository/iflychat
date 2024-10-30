<?php
/**
 *
 * Plugin Name: iFlyChat
 * Plugin URI: http://wordpress.org/extend/plugins/iflychat/
 * Description: One on one chat, Multiple chatrooms, Embedded chatrooms
 * Author: iFlyChat Team
 * Version: 4.7.2
 * Author URI: https://iflychat.com/
 *
 * @package iflychat
 * @version 4.7.2
 *
 * Exit if accessed directly
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Access Denied' );
}

if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
	require_once ABSPATH . '/wp-admin/includes/plugin.php';
}

if ( '' === session_id() ) {
	session_start();
}

if ( ! defined( 'DRUPALCHAT_EXTERNAL_HOST' ) ) {
	define( 'DRUPALCHAT_EXTERNAL_HOST', 'http://api.iflychat.com' );
}

if ( ! defined( 'DRUPALCHAT_EXTERNAL_PORT' ) ) {
	define( 'DRUPALCHAT_EXTERNAL_PORT', '80' );
}

if ( ! defined( 'DRUPALCHAT_EXTERNAL_A_HOST' ) ) {
	define( 'DRUPALCHAT_EXTERNAL_A_HOST', 'https://api.iflychat.com' );
}

if ( ! defined( 'DRUPALCHAT_EXTERNAL_A_PORT' ) ) {
	define( 'DRUPALCHAT_EXTERNAL_A_PORT', '443' );
}

if ( ! defined( 'DRUPALCHAT_EXTERNAL_CDN_HOST' ) ) {
	define( 'DRUPALCHAT_EXTERNAL_CDN_HOST', 'cdn.iflychat.com' );
}

if ( ! defined( 'CHATCAMP_EXTERNAL_HOST' ) ) {
	define( 'CHATCAMP_EXTERNAL_HOST', 'http://api.chatcamp.io' );
}

if ( ! defined( 'CHATCAMP_EXTERNAL_PORT' ) ) {
	define( 'CHATCAMP_EXTERNAL_PORT', '80' );
}

if ( ! defined( 'CHATCAMP_EXTERNAL_A_HOST' ) ) {
	define( 'CHATCAMP_EXTERNAL_A_HOST', 'https://api.chatcamp.io' );
}

if ( ! defined( 'CHATCAMP_EXTERNAL_A_PORT' ) ) {
	define( 'CHATCAMP_EXTERNAL_A_PORT', '443' );
}

if ( ! defined( 'CHATCAMP_EXTERNAL_CDN_HOST' ) ) {
	define( 'CHATCAMP_EXTERNAL_CDN_HOST', 'cdn.chatcamp.io' );
}

define( 'IFLYCHAT_PLUGIN_VERSION', 'WP-4.7.1' );
if ( ! defined( 'IFLYCHAT_DEBUG' ) ) {
	define( 'IFLYCHAT_DEBUG', false );
}


/* define constants */
if ( ! defined( 'IFLYCHAT_DIR' ) ) {
	define( 'IFLYCHAT_DIR', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'IFLYCHAT_URL' ) ) {
	define( 'IFLYCHAT_URL', plugin_dir_url( __FILE__ ) );
}

$iflychat_engine = true;

/**
 * Function to get Session Token.
 *
 * @since 4.7.1
 * @return String $session_token as String.
 */
function iflychat_get_hash_session() {
	$data = uniqid( mp_rand(), true );
	$hash = base64_encode( hash( 'sha256', $data, true ) );

	$session_token = strtr(
		$hash,
		array(
			'+' => '-',
			'/' => '_',
			'=' => '',
		)
	);
	return $session_token;
}

/**
 * Function to get User ID.
 *
 * @since 4.7.1
 * @return String user ID as String.
 */
function iflychat_get_user_id() {
	$current_user = wp_get_current_user();
	if ( $current_user->ID ) {
		return strval( $current_user->ID );
	} else {
		return false;
	}
}

/**
 * Function to get User's Display Name.
 *
 * @since 4.7.1
 * @return String user's Display Name as String or false.
 */
function iflychat_get_user_name() {
	$current_user   = wp_get_current_user();
	$hook_user_name = apply_filters( 'iflychat_get_username_filter', '', $current_user->ID );

	if ( ! empty( $hook_user_name ) ) {
		return $hook_user_name;
	}

	if ( $current_user->ID ) {
		if ( ! isset( $current_user->display_name ) || '' === trim( $current_user->display_name ) || ( '2' === iflychat_get_option( 'iflychat_use_display_name' ) ) ) {
			return $current_user->user_login;
		} else {
			return $current_user->display_name;
		}
	} else {
		return false;
	}
}


/**
 * Function to load script Async.
 *
 * @since 4.7.1
 * @param String $url String.
 * @return String $url String.
 */
function iflychat_async_scripts( $url ) {
	if ( false === strpos( $url, '#asyncload' ) ) {
		return $url;
	} elseif ( is_admin() ) {
		return str_replace( '#asyncload', '', $url ) . "' async='async";
	} else {
		return str_replace( '#asyncload', '', $url ) . "' async='async";
	}
}
add_filter( 'clean_url', 'iflychat_async_scripts' );

/**
 * Function to Initialise the plugin.
 *
 * @since 4.7.1
 */
function iflychat_init() {
	$user_data = false;
	if ( iflychat_check_access() ) {
		$_iflychat_protocol = isset( $_SERVER['HTTPS'] ) ? 'https://' : 'http://';

		wp_enqueue_script( 'iflychat-ajax', IFLYCHAT_URL . 'js/iflychat.js', array( 'jquery' ), filemtime( IFLYCHAT_DIR . 'js/iflychat.js' ), true );
		wp_localize_script( 'iflychat-ajax', 'iflychat_chatcamp_check', iflychat_chatcamp_check() ? '1' : '0' );
		wp_localize_script( 'iflychat-ajax', 'iflychat_app_id', iflychat_get_option( 'iflychat_app_id' ) );
		wp_localize_script( 'iflychat-ajax', 'iflychat_external_cdn_host', iflychat_chatcamp_check() ? CHATCAMP_EXTERNAL_CDN_HOST : DRUPALCHAT_EXTERNAL_CDN_HOST );

		wp_localize_script(
			'iflychat-ajax',
			'iflychat_ajax',
			array(
				'ajax_nonce' => wp_create_nonce( 'iflychat_ajax_nonce' ),
			)
		);

		if ( is_user_logged_in() ) {
			$user_data = wp_json_encode( _iflychat_get_user_auth() );
		}

		if ( '1' === iflychat_get_option( 'iflychat_session_caching' ) && isset( $_SESSION['user_data'] ) && $user_data === $_SESSION['user_data'] ) {
			if ( isset( $_SESSION['token'] ) && ! empty( $_SESSION['token'] ) ) {
				wp_localize_script( 'iflychat-ajax', 'iflychat_auth_token', sanitize_text_field( wp_unslash( $_SESSION['token'] ) ) );
			}
		}
		if ( is_user_logged_in() ) {
			wp_localize_script( 'iflychat-ajax', 'iflychat_auth_url', admin_url( 'admin-ajax.php', $_iflychat_protocol ) );
		}

		if ( '1' === iflychat_get_option( 'iflychat_popup_chat' ) ) {
			wp_enqueue_script( 'iflychat-popup', IFLYCHAT_URL . 'js/iflychat-popup.js', array(), filemtime( IFLYCHAT_DIR . 'js/iflychat-popup.js' ), true );
		} elseif ( '2' === iflychat_get_option( 'iflychat_popup_chat' ) && ! is_admin() ) {
			wp_enqueue_script( 'iflychat-popup', IFLYCHAT_URL . 'js/iflychat-popup.js', array(), filemtime( IFLYCHAT_DIR . 'js/iflychat-popup.js' ), true );
		} elseif ( ( '3' === iflychat_get_option( 'iflychat_popup_chat' ) || '4' === iflychat_get_option( 'iflychat_popup_chat' ) ) && iflychat_path_check() ) {
			wp_enqueue_script( 'iflychat-popup', IFLYCHAT_URL . 'js/iflychat-popup.js', array(), filemtime( IFLYCHAT_DIR . 'js/iflychat-popup.js' ), true );
		}

		/*wp_localize_script(
			'iflychat-popup',
			'iflychat_popup_ajax',
			array(
				'ajax_nonce' => wp_create_nonce( 'iflychat_popup_ajax_nonce' ),
			)
		);*/
	}
}

/**
 * Function to get user_details
 *
 * @since 4.7.1
 */
function _iflychat_get_user_auth() {
	$current_user = wp_get_current_user();
	$admin_check  = false;
	$user_data    = array();

	if ( iflychat_check_chat_admin() ) {
		$chat_role = 'admin';
	} elseif ( iflychat_check_chat_moderator() ) {
		$chat_role = 'moderator';
	} else {
		$chat_role = 'participant';
	}
	$role = array();
	if ( count( $current_user->roles ) > 0 ) {
		foreach ( $current_user->roles as $rkey => $rvalue ) {
			$role[ $rvalue ] = $rvalue;
		}
	}

	if ( iflychat_get_user_id() && iflychat_get_user_name() ) {
		$user_data = array(
			'user_id'          => iflychat_get_user_id(),
			'user_name'        => iflychat_get_user_name(),
			'user_roles'       => $role,
			'chat_role'        => $chat_role,
			'user_list_filter' => 'all',
			'user_status'      => true,
		);
	}

	$user_data['user_avatar_url']  = iflychat_get_user_pic_url();
	$user_data['user_profile_url'] = iflychat_get_user_profile_url();

	// Added allRoles if chat_role is admin or moderator.
	if ( 'admin' === $chat_role || 'moderator' === $chat_role ) {
		global $wp_roles;
		$user_data['user_site_roles'] = $wp_roles->get_names();
	}

	$hook_user_groups  = apply_filters( 'iflychat_get_user_groups_filter', array(), $current_user->ID );
	$hook_user_friends = apply_filters( 'iflychat_get_user_friends_filter', array(), $current_user->ID );
	$hook_user_roles   = apply_filters( 'iflychat_get_user_roles_filter', array(), $current_user->ID );
	if ( ( '2' === iflychat_get_option( 'iflychat_enable_friends' ) ) && function_exists( 'friends_get_friend_user_ids' ) ) { // filtering based on buddypress friends.
		$user_data['user_list_filter']   = 'friend';
		$final_list                      = array();
		$final_list['1']['name']         = 'friend';
		$final_list['1']['plural']       = 'friends';
		$final_list['1']['valid_uids']   = friends_get_friend_user_ids( iflychat_get_user_id() );
		$user_data['user_relationships'] = $final_list;
	} else {
		$user_data['user_list_filter'] = 'all';
	}
	if ( ! empty( $hook_user_friends ) ) {
		if ( '2' !== iflychat_get_option( 'iflychat_enable_friends' ) ) {
			iflychat_update_option( 'iflychat_enable_friends', '2' );
		}
		$user_data['user_list_filter']   = 'friend';
		$final_list                      = array();
		$final_list['1']['name']         = 'friend';
		$final_list['1']['plural']       = 'friends';
		$final_list['1']['valid_uids']   = $hook_user_friends;
		$user_data['user_relationships'] = $final_list;
	}

	if ( ! empty( $hook_user_groups ) ) {
		$user_data['user_list_filter'] = 'group';
		$user_data['user_groups']      = $hook_user_groups;
		if ( '1' !== iflychat_get_option( 'iflychat_enable_user_groups' ) ) {
			iflychat_update_option( 'iflychat_enable_user_groups', '1' );
		}
	}
	if ( empty( $hook_user_groups ) ) {
		if ( '2' !== iflychat_get_option( 'iflychat_enable_user_groups' ) ) {
			iflychat_update_option( 'iflychat_enable_user_groups', '2' );
		}
	}

	if ( ! empty( $hook_user_roles ) ) {
		$user_data['user_roles'] = $hook_user_roles;
	}
	return $user_data;
}

/**
 * Function to get User authentication
 *
 * @since 4.7.1
 */
function _iflychat_get_auth() {
	$current_user = wp_get_current_user();
	global $wp_version;
	$data = array();

	if ( '' === trim( iflychat_get_option( 'iflychat_api_key' ) ) ) {
		return null;
	}

	$admin_check = false;
	if ( iflychat_check_chat_admin() ) {
		$chat_role = 'admin';
	} elseif ( iflychat_check_chat_moderator() ) {
		$chat_role = 'moderator';
	} else {
		$chat_role = 'participant';
	}

	$role = array();
	if ( count( $current_user->roles ) > 0 ) {
		foreach ( $current_user->roles as $rkey => $rvalue ) {
			$role[ $rvalue ] = $rvalue;
		}
	}

	if ( iflychat_get_user_id() && iflychat_get_user_name() ) {
		$data = array(
			'api_key' => iflychat_get_option( 'iflychat_api_key' ),
			'app_id'  => iflychat_get_option( 'iflychat_app_id' ) ? iflychat_get_option( 'iflychat_app_id' ) : '',
			'version' => IFLYCHAT_PLUGIN_VERSION,
		);
	}

	$user_data             = _iflychat_get_user_auth();
	$data                  = array_merge( $data, $user_data );
	$_SESSION['user_data'] = wp_json_encode( $user_data );

	$options = array(
		'method'    => 'POST',
		'body'      => $data,
		'timeout'   => 15,
		'headers'   => array(
			'Content-Type' => 'application/x-www-form-urlencoded',
		),
		'sslverify' => false,
	);

	if ( iflychat_chatcamp_check() ) {

		$options['body'] = wp_json_encode(
			array(
				'id' => $data['user_id'],
			)
		);

		$options['headers'] = array(
			'Content-Type' => 'application/json',
			'x-api-key'    => $data['api_key'],
		);

		$result = wp_remote_head( CHATCAMP_EXTERNAL_A_HOST . ':' . CHATCAMP_EXTERNAL_A_PORT . '/api/2.0/users.get', $options );
		if ( ! is_wp_error( $result ) && 200 === $result['response']['code'] ) {
			$result = json_decode( $result['body'] );
			if ( is_user_logged_in() ) {
				$_SESSION['token']    = $result->access_token;
				$result->current_user = $current_user;
				$result->test_data    = $data;
				$should_update        = false;
				$should_update        = iflychat_chatcamp_user_should_update( $data, $result->user );
				if ( true === $should_update ) {
					$options['body'] = wp_json_encode( iflychat_chatcamp_process_user_data( $data ) );
					$result          = wp_remote_head( CHATCAMP_EXTERNAL_A_HOST . ':' . CHATCAMP_EXTERNAL_A_PORT . '/api/2.0/users.update', $options );
					if ( ! is_wp_error( $result ) && 200 === $result['response']['code'] ) {
						$result = json_decode( $result['body'] );
						if ( is_user_logged_in() ) {
							$_SESSION['token']    = $result->access_token;
							$result->current_user = $current_user;
						}
						return $result;
					} elseif ( ! is_wp_error( $result ) && 200 !== $result['response']['code'] ) {
						return $result['response'];
					} else {
						$error = array(
							'code'    => $result->get_error_code(),
							'message' => $result->get_error_message(),
						);
						return $error;
					}
				}
			}
			return $result;
		} elseif ( 404 === $result['response']['code'] ) {
			$options['body'] = wp_json_encode( iflychat_chatcamp_process_user_data( $data ) );
			$result          = wp_remote_head( CHATCAMP_EXTERNAL_A_HOST . ':' . CHATCAMP_EXTERNAL_A_PORT . '/api/2.0/users.create', $options );
			if ( ! is_wp_error( $result ) && 200 === $result['response']['code'] ) {
				$result = json_decode( $result['body'] );
				if ( is_user_logged_in() ) {
					$_SESSION['token']    = $result->access_token;
					$result->current_user = $current_user;
				}
				return $result;
			} elseif ( ! is_wp_error( $result ) && 200 !== $result['response']['code'] ) {
				return $result['response'];
			} else {
				$error = array(
					'code'    => $result->get_error_code(),
					'message' => $result->get_error_message(),
				);
				return $error;
			}
		} elseif ( ! is_wp_error( $result ) && 200 !== $result['response']['code'] ) {
			return $result['response'];
		} else {
			$error = array(
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
			);
			return $error;
		}
	} else {
		$result = wp_remote_head( iflychat_get_host( true ) . ':' . DRUPALCHAT_EXTERNAL_A_PORT . '/api/1.1/token/generate', $options );
		if ( ! is_wp_error( $result ) && 200 === $result['response']['code'] ) {
			$result = json_decode( $result['body'] );
			if ( is_user_logged_in() ) {
				$_SESSION['token'] = $result->key;
			}
			return $result;
		} elseif ( ! is_wp_error( $result ) && 200 !== $result['response']['code'] ) {
			return $result['response'];
		} else {
			$error = array(
				'code'    => $result->get_error_code(),
				'message' => $result->get_error_message(),
			);
			return $error;
		}
	}
}

/**
 * Function to get mobile authentication
 *
 * @since 4.7.1
 */
function iflychat_mobile_auth() {
	if ( check_ajax_referer( 'iflychat_ajax_nonce', 'nonce' ) ) {
		if ( '1' === iflychat_get_option( 'iflychat_enable_mobile_sdk_integration', '2' ) ) {
			$username = isset( $_POST['username'] ) ? sanitize_text_field( wp_unslash( $_POST['username'] ) ) : '';
			$password = isset( $_POST['password'] ) ? sanitize_text_field( wp_unslash( $_POST['password'] ) ) : '';

			$uid = wp_authenticate_username_password( null, $username, $password );
			$id  = ( $uid->data->ID );
			if ( '' !== trim( $id ) ) {
				$user = wp_set_current_user( $id, $username );
				header( 'Content-Type: application/json' );
				echo wp_json_encode( _iflychat_get_auth( $username ) );
			} else {
				header( 'HTTP/1.1 403 Access Denied' );
				echo esc_html( 'Access Denied' );
			}
		} else {
			header( 'HTTP/1.1 403 Access Denied' );
			echo esc_html( 'Please Enable Mobile SDK Integration' );
		}
	}
	exit;
}

/**
 * Function to Submit chat
 *
 * @since 4.7.1
 */
function iflychat_submit_uth() {
	if ( check_ajax_referer( 'iflychat_ajax_nonce', 'nonce' ) ) {
		$json = null;
		$json = _iflychat_get_auth();

		header( 'Content-Type: application/json' );
		echo wp_json_encode( $json );
	}
	exit;
}

/**
 * Function to Install plugin
 *
 * @since 4.7.1
 */
function iflychat_install() {
	global $wpdb;
}

/**
 * Function to uninstall plugin
 *
 * @since 4.7.1
 */
function iflychat_uninstall() {
	global $wpdb;
}

/**
 * Function to Set Settings option
 *
 * @since 4.7.1
 */
function iflychat_set_options() {
	$options = array(
		'app_id'                => array(
			'name'          => 'iflychat_app_id',
			'default'       => ' ',
			'desc'          => '<b>APP ID</b> (register at <a href="https://iflychat.com">iFlyChat.com</a> to get it)',
			'input_type'    => 'text',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'api_key'               => array(
			'name'          => 'iflychat_api_key',
			'default'       => ' ',
			'desc'          => '<b>API key</b> (register at <a href="https://iflychat.com">iFlyChat.com</a> to get it)',
			'input_type'    => 'text',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'use_display_name'      => array(
			'name'          => 'iflychat_use_display_name',
			'default'       => '1',
			'desc'          => 'Specify whether to use display name or username for logged-in user',
			'input_type'    => 'dropdown',
			'data'          => array(
				'1' => 'Display Name',
				'2' => 'Username',
			),
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'embed_chat'            => array(
			'name'          => 'iflychat_embed_chat',
			'desc'          => 'Show embed chat',
			'default'       => 'View Tutorial',
			'input_type'    => 'button',
			'link'          => 'https://iflychat.com/embedded-chatroom-example-public-chatroom',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'enable_friends'        => array(
			'name'          => 'iflychat_enable_friends',
			'default'       => '1',
			'desc'          => 'Show only friends in online user list',
			'input_type'    => 'dropdown',
			'data'          => array(
				'1' => 'No',
				'2' => 'BuddyPress Friends',
			),
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'popup_chat'            => array(
			'name'          => 'iflychat_popup_chat',
			'default'       => '1',
			'desc'          => 'Show Popup Chat',
			'input_type'    => 'dropdown',
			'data'          => array(
				'1' => 'Everywhere',
				'2' => 'Frontend Only',
				'3' => 'Everywhere except those listed',
				'4' => 'Only the listed pages',
				'5' => 'Disable',
			),
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
		'path_pages'            => array(
			'name'          => 'iflychat_path_pages',
			'default'       => '',
			'desc'          => "Specify pages by using their paths. Enter one path per line. The '*' character is a wildcard. Example paths are <b>/2012/10/my-post</b> for a single post and <b>/2012/*</b> for a group of posts. The path should always start with a forward slash(/).",
			'input_type'    => 'textarea',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
			),
		),
		'chat_moderators_array' => array(
			'name'          => 'iflychat_chat_moderators_array',
			'default'       => '',
			'desc'          => 'Specify WordPress username of users who should be chat moderators (separated by comma)',
			'input_type'    => 'textarea',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
			),
		),
		'chat_admins_array'     => array(
			'name'          => 'iflychat_chat_admins_array',
			'default'       => '',
			'desc'          => 'Specify WordPress username of users who should be chat admininstrators (separated by comma)',
			'input_type'    => 'textarea',
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_textarea_field',
			),
		),
		'session_caching'       => array(
			'name'          => 'iflychat_session_caching',
			'default'       => '2',
			'desc'          => 'Enable Session Caching',
			'input_type'    => 'dropdown',
			'data'          => array(
				'1' => 'Yes',
				'2' => 'No',
			),
			'sanitize_data' => array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			),
		),
	);

	return $options;

}

/**
 * Function to create Settings page
 *
 * @since 4.7.1
 */
function iflychat_settings() {

	wp_enqueue_script( 'iflychat-admin', IFLYCHAT_URL . 'js/iflychat.admin.script.js', array(), filemtime( IFLYCHAT_DIR . 'js/iflychat.admin.script.js' ), true );

	wp_localize_script(
		'iflychat-admin',
		'iflychat_admin_ajax',
		array(
			'ajax_url'   => admin_url( 'admin-ajax.php' ),
			'ajax_nonce' => wp_create_nonce( 'iflychat_admin_ajax_nonce' ),
		)
	);

	$default_tab = 'plugin_settings';
	if ( isset( $_POST['iflychat_network_settings_form_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['iflychat_network_settings_form_nonce'] ) ), 'iflychat_network_settings_form' ) ) {
		$default_tab = 'plugin_settings';
	}

	$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : $default_tab;
	$i          = 0;
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'iFlyChat Settings', 'iflychat_settings' ); ?></h1>
		<h2 class="nav-tab-wrapper">
			<a href="?page=iflychat_settings&tab=plugin_settings" class="nav-tab <?php echo esc_attr( 'plugin_settings' === $active_tab ) ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Plugin Settings', 'iflychat_settings' ); ?></a>
			<a href="?page=iflychat_settings&tab=app_settings" class="nav-tab <?php echo esc_attr( 'app_settings' === $active_tab ) ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'App Settings', 'iflychat_settings' ); ?></a>
		</h2>
		<?php
		if ( 'plugin_settings' === $active_tab ) {
			$result = _iflychat_get_auth();
			if ( is_array( $result ) ) {

				if ( 403 === $result['code'] ) {
					?>
					<div id="message" class="error"><p><strong><?php esc_html_e( 'Invalid API Key.', 'iflychat_settings' ); ?></strong></p></div>
					<?php
				} elseif ( 503 === $result['code'] ) {
					?>
					<div id="message" class="error"><p><strong><?php esc_html_e( '503 Error. Service Unavailable.', 'iflychat_settings' ); ?></strong></p></div>
					<?php
				} else {
					$msg = 'Error Message - ' . $result['message'] . '. Error Code - ' . $result['code'];
					?>
					<div id="message" class="error"><p><strong><?php echo esc_attr( $msg ); ?></strong></p></div>
					<?php
				}
			}

			if ( iflychat_validate_fields() ) {
				if ( isset( $_GET['updated'] ) && 'true' === trim( sanitize_text_field( wp_unslash( $_GET['updated'] ) ) ) ) {
					?>
					<div id="message" class="updated fade"><p><strong><?php esc_html_e( 'Settings Updated', 'iflychat_settings' ); ?></strong></p></div>
					<?php
				}
			} else {
				?>
				<div id="message" class="error"><p><strong><?php esc_html_e( 'Invalid APP ID.', 'iflychat_settings' ); ?></strong></p></div>
				<?php
			}
			$action_url = '';
			if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
				$action_url = 'edit.php?action=iflychat_network_settings';
			} else {
				$action_url = 'options.php';
			}
			?>
			<form method="post" action="<?php echo esc_url( $action_url ); ?>">
				<div>
					<?php
					settings_fields( 'iflychat-settings' );
					wp_nonce_field( 'iflychat_network_settings_form', 'iflychat_network_settings_form_nonce' );
					?>
				</div>

				<?php
				$options = iflychat_set_options();
				?>
				<table class="form-table">
					<?php
					if ( count( $options ) > 0 ) {
						foreach ( $options as $option ) {
							$opt_name = iflychat_get_option( $option['name'] );

							if ( 'dropdown' === $option['input_type'] ) {
								?>
								<tr valign="top">
									<th scope="row"><?php echo wp_kses_post( $option['desc'] ); ?></th>
									<td>
										<select id="<?php echo esc_attr( $option['name'] ); ?>" name="<?php echo esc_attr( $option['name'] ); ?>">
											<?php
											foreach ( $option['data'] as $opt => $value ) {
												?>
													<option <?php echo esc_attr( trim( $opt_name ) === trim( $opt ) ? 'selected="selected"' : '' ); ?> value="<?php echo esc_attr( $opt ); ?>"><?php echo esc_attr( $value ); ?></option>
												<?php
											} //endforeach
											?>
										</select>
									</td>
								</tr>
								<?php
								// If option type is text, do this.
							} elseif ( 'text' === $option['input_type'] ) {
								?>
								<tr valign="top">
									<th scope="row"><?php echo wp_kses_post( $option['desc'] ); ?></th>
									<td><input id="<?php echo esc_attr( $option['name'] ); ?>" name="<?php echo esc_attr( $option['name'] ); ?>" value="<?php echo esc_attr( $opt_name ); ?>" size="64" />
									</td>
								</tr>
								<?php
								// If option type is text, do this.
							} elseif ( 'textarea' === $option['input_type'] ) {
								?>
								<tr valign="top" id="<?php echo esc_attr( 'iflychat_path_pages' === $option['name'] ? $option['name'] : '' ); ?>">
									<th scope="row"><?php echo wp_kses_post( $option['desc'] ); ?></th>
									<td><textarea  cols="80" rows="6" name="<?php echo esc_attr( $option['name'] ); ?>"><?php echo esc_attr( trim( $opt_name ) ); ?>
											</textarea>
									</td>
								</tr>
								<?php
							} elseif ( 'button' === $option['input_type'] ) {
								?>
								<tr valign="top">
									<th scope="row"><?php echo wp_kses_post( $option['desc'] ); ?></th>
									<td><a target="_blank" href="<?php echo esc_url( $option['link'] ); ?>"><input type="button" value="<?php echo esc_attr( $option['default'] ); ?>"></a>
									</td>
								</tr>
								<?php
							}
						}//endforeach
					}
					?>
				</table>
				<p class="submit"><input type="submit" class="button-primary" value="<?php esc_html_e( 'Update', 'iflychat_settings' ); ?>" /></p>
			</form>		
			<br />
			<hr />
			<br />
			<h3><?php esc_html_e( 'Debug Information', 'iflychat_settings' ); ?></h3>
			<p>
				<?php esc_html_e( 'Having problems with iFlyChat? Check out our installation guide', 'iflychat_settings' ); ?>
				<a href="https://iflychat.com/installation/wordpress-chat-plugin" target="_blank"><?php esc_html_e( 'here', 'iflychat_settings' ); ?></a>
				<?php esc_html_e( '. You can also open a support ticket and we will look into it immediately. Please include the debug information given below.', 'iflychat_settings' ); ?>
				<a href="https://iflychat.com/contact" target="_blank"><?php esc_html_e( 'Contact support', 'iflychat_settings' ); ?></a>
			</p>
			<?php
			global $wp_version;

			if ( ! function_exists( 'wp_get_theme' ) ) {
				$theme      = wp_get_themes();
				$theme_name = esc_html( $theme['Name'] . ' ' . $theme['Version'] );
			} else {
				$theme      = wp_get_theme();
				$theme_name = esc_html( $theme->get( 'Name' ) . ' ' . $theme->get( 'Version' ) );
			}
			?>
			<div style="font-size: 15px;">
				<?php echo esc_html( 'URL : ' ); ?><?php echo esc_url( get_option( 'siteurl' ) ); ?><br/>
				<?php echo esc_html( 'PHP Version : ' ); ?><?php echo esc_html( phpversion() ); ?><br/>
				<?php echo esc_html( 'WordPress Version : ' ); ?><?php echo esc_html( $wp_version ); ?><br/>
				<?php echo esc_html( 'Active Theme : ' ); ?><?php echo esc_attr( $theme_name ); ?><br/>
				<?php echo esc_html( 'URL Open Method : ' ); ?><?php echo esc_html( iflychat_url_method() ); ?><br/>
				<?php echo esc_html( 'Plugin Version : ' ); ?><?php echo esc_html( IFLYCHAT_PLUGIN_VERSION ); ?><br/>
				<?php echo esc_html( 'Settings: iflychat_is_installed: ' ); ?><?php echo esc_html( iflychat_is_installed() . ' | ' ); ?>
				<?php
				foreach ( iflychat_options() as $opt ) {
					echo esc_html( ' ' . $opt . ' : ' . get_option( $opt ) . ' | ' );
				}
				?>
				<br/>
				<?php echo esc_html( 'Plugins : ' ); ?>
				<?php
				foreach ( get_plugins() as $key => $plugin ) {
					$isactive = '';
					if ( is_plugin_active( $key ) ) {
						$isactive = '(active)';
					}
					echo esc_html( ' ' . $plugin['Name'] . ' ' . $plugin['Version'] . ' ' . $isactive . ' | ' );
				}
				?>
			</div>
			<br/>
			<?php
		} else {
			$dashboard_url = 'https://dashboard.chatcamp.io';
			if ( ! iflychat_chatcamp_check() ) {
				$iflychat_host = DRUPALCHAT_EXTERNAL_A_HOST;

				$host      = explode( '/', $iflychat_host );
				$host_name = isset( $host[2] ) ? $host[2] : '';
				if ( isset( $_SESSION['token'] ) && ! empty( $_SESSION['token'] ) ) {
					$token = sanitize_text_field( wp_unslash( $_SESSION['token'] ) );
				} else {
					$token = _iflychat_get_auth()->key;
				}
				$dashboard_url = 'https://cdn.iflychat.com/apps/dashboard/#/settings/app?sessid=' . $token . '&hostName=' . $host_name . '&hostPort=' . DRUPALCHAT_EXTERNAL_A_PORT;
			}
			?>
			<br/>
			<input type="button" class="button-primary" value="Open App Dashboard in new tab" onclick="window.open( '<?php echo esc_url( $dashboard_url ); ?>')">
			<?php
		}
		?>
	</div>
	<?php
}


/**
 * Function to check if iflychat is installed
 *
 * @since 4.7.1
 */
function iflychat_is_installed() {
	$iflychat_api_key = get_option( 'iflychat_api_key' );
	$iflychat_app_id  = get_option( 'iflychat_app_id' );
	if ( strlen( trim( $iflychat_api_key ) ) > 0 && strlen( trim( $iflychat_app_id ) ) > 0 ) {
		return true;
	} else {
		return false;
	}
}

/**
 * Function to array of settings options.
 *
 * @since 4.7.1
 * @return Array settings options as Array.
 */
function iflychat_options() {
	return array(
		'iflychat_app_id',
		'iflychat_api_key',
		'iflychat_use_display_name',
		'iflychat_enable_friends',
		'iflychat_popup_chat',
		'iflychat_path_pages',
		'iflychat_chat_moderators_array',
		'iflychat_chat_admins_array',
		'iflychat_session_caching',
	);
}

/**
 * Function to get url method.
 *
 * @since 4.7.1
 * @return String URL method as String.
 */
function iflychat_url_method() {
	if ( function_exists( 'curl_init' ) ) {
		return 'curl';
	} elseif ( ini_get( 'allow_url_fopen' ) && function_exists( 'stream_get_contents' ) ) {
		return 'fopen';
	} else {
		return 'fsockopen';
	}
}

/**
 * Function to add settings page.
 *
 * @since 4.7.1
 */
function iflychat_settings_page() {
	if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		add_submenu_page( 'settings.php', 'iFlyChat Settings', 'iFlyChat Settings', 'manage_options', 'iflychat_settings', 'iflychat_settings' );
	} else {
		add_options_page( 'iFlyChat Settings', 'iFlyChat Settings', 'manage_options', 'iflychat_settings', 'iflychat_settings' );
	}
}

/**
 * Function to register settings loops through options.
 *
 * @since 4.7.1
 */
function iflychat_register_settings() {
	$options = iflychat_set_options();
	foreach ( $options as $option ) {
			register_setting(
				'iflychat-settings',
				$option['name'],
				$option['sanitize_data'],
			);

		// register each setting with option's 'name'.
		if ( iflychat_get_option( $option['name'] ) === false ) {
			iflychat_add_option( $option['name'], $option['default'], '', 'yes' ); // set option defaults.
		}
	}
}
add_action( 'admin_init', 'iflychat_register_settings' );

/**
 * Function to Validate form fields.
 *
 * @since 4.7.1
 * @return Boolean true or false as Boolean.
 */
function iflychat_validate_fields() {
	$app_id = iflychat_get_option( 'iflychat_app_id' );
	if ( iflychat_chatcamp_check() || ( 36 === strlen( $app_id ) && '4' === $app_id[14] ) ) {
		return true;
	} else {
		return false;
	}
}

if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
	add_action( 'network_admin_menu', 'iflychat_settings_page' );
} else {
	add_action( 'admin_menu', 'iflychat_settings_page' );
}

/**
 * Function to Update site options.
 *
 * @since 4.7.1
 */
function iflychat_network_settings() {
	if ( isset( $_POST['iflychat_network_settings_form_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['iflychat_network_settings_form_nonce'] ) ), 'iflychat_network_settings_form' ) ) {

		$option_page = ( isset( $_POST['option_page'] ) ? sanitize_text_field( wp_unslash( $_POST['option_page'] ) ) : '' );
		$action      = ( isset( $_POST['action'] ) ? sanitize_text_field( wp_unslash( $_POST['action'] ) ) : '' );

		if ( ( 'iflychat-settings' === $option_page ) && ( 'update' === $action ) ) {

			if ( is_array( $_POST ) && count( $_POST ) > 0 ) {
				foreach ( $_POST as $key => $value ) {
					if ( substr( $key, 0, 9 ) === 'iflychat_' ) {
						update_site_option( $key, trim( sanitize_text_field( wp_unslash( $value ) ) ) );
					}
				}
			}
		}
		// redirect to settings page in network.
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => 'iflychat_settings',
					'updated' => 'true',
				),
				network_admin_url( 'settings.php' ),
			)
		);
		exit;
	}
}

if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
	add_action( 'network_admin_edit_iflychat_network_settings', 'iflychat_network_settings' );
}

add_action( 'init', 'iflychat_init' );
add_action( 'wp_ajax_nopriv_iflychat-mobile-auth', 'iflychat_mobile_auth' );
add_action( 'wp_ajax_iflychat-mobile-auth', 'iflychat_mobile_auth' );
add_action( 'wp_ajax_nopriv_iflychat-get', 'iflychat_submit_uth' );
add_action( 'wp_ajax_iflychat-get', 'iflychat_submit_uth' );
add_action( 'wp_ajax_nopriv_iflychat-offline-msg', 'iflychat_send_offline_message' );
add_action( 'wp_ajax_iflychat-offline-msg', 'iflychat_send_offline_message' );
add_action( 'wp_ajax_nopriv_iflychat-change-guest-name', 'iflychat_change_guest_name' );
add_action( 'wp_login', 'iflychat_user_login' );
add_action( 'wp_logout', 'iflychat_user_logout' );
add_shortcode( 'iflychat_inbox', 'iflychat_get_inbox' );
add_shortcode( 'iflychat_message_thread', 'iflychat_get_message_thread' );
add_shortcode( 'iflychat_embed', 'iflychat_get_embed_code' );
register_activation_hook( __FILE__, 'iflychat_install' );
register_deactivation_hook( __FILE__, 'iflychat_uninstall' );

/**
 * Function to check path match or not.
 *
 * @since 4.7.1
 * @param String $path path name as string.
 * @param String $patterns path name as string.
 * @return Boolean true or false as Boolean.
 */
function iflychat_match_path( $path, $patterns ) {
	$to_replace   = array(
		'/(\r\n?|\n)/',
		'/\\\\\*/',
	);
	$replacements = array(
		'|',
		'.*',
	);

	$patterns_quoted      = preg_quote( $patterns, '/' );
	$regexps[ $patterns ] = '/^(' . preg_replace( $to_replace, $replacements, $patterns_quoted ) . ')$/';
	return (bool) preg_match( $regexps[ $patterns ], $path );
}

/**
 * Function to check path check.
 *
 * @since 4.7.1
 * @return Boolean $page_match true or false Boolean.
 */
function iflychat_path_check() {
	$page_match = false;

	$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

	if ( function_exists( 'mb_strtolower' ) ) {
		$pages = mb_strtolower( iflychat_get_option( 'iflychat_path_pages' ) );
		$path  = mb_strtolower( $request_uri );
	} else {
		$pages = strtolower( iflychat_get_option( 'iflychat_path_pages' ) );
		$path  = strtolower( $request_uri );
	}
	$page_match = iflychat_match_path( $path, $pages );

	if ( '3' === iflychat_get_option( 'iflychat_popup_chat' ) ) {
		$page_match = ! $page_match;
	}
	if ( '4' === iflychat_get_option( 'iflychat_popup_chat' ) ) {
		$page_match = $page_match;
	}
	if ( '1' === iflychat_get_option( 'iflychat_popup_chat' ) ) {
		$page_match = true;
	}
	return $page_match;
}

/**
 * Function to return content type.
 *
 * @since 4.7.1
 * @return string content type as string.
 */
function iflychat_mail_set_content_type() {
	return 'text/html';
}

/**
 * Function to send ofline message.
 *
 * @since 4.7.1
 */
function iflychat_send_offline_message() {
	if ( check_ajax_referer( 'iflychat_ajax_nonce', 'nonce' ) ) {
		$contact_details      = isset( $_POST['drupalchat_m_contact_details'] ) ? sanitize_textarea_field( wp_unslash( $_POST['drupalchat_m_contact_details'] ) ) : '';
		$drupalchat_m_message = isset( $_POST['drupalchat_m_message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['drupalchat_m_message'] ) ) : '';

		if ( isset( $contact_details ) && isset( $drupalchat_m_message ) ) {
			global $user;
			$drupalchat_offline_mail                    = array();
			$drupalchat_offline_mail['subject']         = 'iFlyChat: Message from Customer';
			$drupalchat_offline_mail['contact_details'] = '<p>' . iflychat_get_option( 'iflychat_support_chat_offline_message_contact' ) . ': ' . ( $contact_details ) . '</p>';
			$drupalchat_offline_mail['message']         = '<p>' . iflychat_get_option( 'iflychat_support_chat_offline_message_label' ) . ': ' . ( $drupalchat_m_message ) . '</p>';
			$drupalchat_offline_mail['message']         = $drupalchat_offline_mail['contact_details'] . '<br><br>' . $drupalchat_offline_mail['message'];
			add_filter( 'wp_mail_content_type', 'iflychat_mail_set_content_type' );
			$result = wp_mail( iflychat_get_option( 'iflychat_support_chat_offline_message_email' ), $drupalchat_offline_mail['subject'], $drupalchat_offline_mail['message'] );
		}

		header( 'Content-Type: application/json' );
		echo wp_json_encode( $result );
	}
	exit;
}

/**
 * Function to check admin chat.
 *
 * @since 4.7.1
 * @return Boolean admin chat true or false as Boolean.
 */
function iflychat_check_chat_admin() {

	$current_user = wp_get_current_user();
	if ( current_user_can( 'activate_plugins' ) ) {
		return true;
	}

	$a = iflychat_get_option( 'iflychat_chat_admins_array' );
	if ( ! empty( $a ) && ( $current_user->ID ) ) {
		$a_names = explode( ',', $a );
		foreach ( $a_names as $an ) {
			$aa = trim( $an );
			if ( $aa === $current_user->user_login ) {
				return true;
			}
		}
	}
	return false;
}

/**
 * Function to check chat is moderator.
 *
 * @since 4.7.1
 * @return Boolean chat moderator true or false as Boolean.
 */
function iflychat_check_chat_moderator() {
	$current_user = wp_get_current_user();

	$a = iflychat_get_option( 'iflychat_chat_moderators_array' );
	if ( ! empty( $a ) && ( $current_user->ID ) ) {
		$a_names = explode( ',', $a );
		foreach ( $a_names as $an ) {
			$aa = trim( $an );
			if ( $aa === $current_user->user_login ) {
				return true;
			}
		}
	}
	return false;
}

/**
 * Function to destroy session ( session unset ).
 *
 * @since 4.7.1
 */
function iflychat_token_destroy() {
	$data = array(
		'api_key' => iflychat_get_option( 'iflychat_api_key' ),
	);

	$options = array(
		'method'    => 'POST',
		'body'      => $data,
		'timeout'   => 15,
		'headers'   => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
		'sslverify' => false,
	);

	$result = wp_remote_head(
		iflychat_get_host( true ) . ':' . DRUPALCHAT_EXTERNAL_A_PORT . '/api/1.1/token/'
		. $_SESSION['token'] . '/delete',
		$options
	);
	session_unset();
}

/**
 * Function to set cookie for user login.
 *
 * @since 4.7.1
 */
function iflychat_user_login() {
	setcookie( 'iflychat_key', '', time() - 3600, '/' );
	setcookie( 'iflychat_css', '', time() - 3600, '/' );
	setcookie( 'iflychat_time', '', time() - 3600, '/' );
}

/**
 * Function to set cookie and destroy token for user logout.
 *
 * @since 4.7.1
 */
function iflychat_user_logout() {
	setcookie( 'iflychat_key', '', time() - 3600, '/' );
	setcookie( 'iflychat_css', '', time() - 3600, '/' );
	setcookie( 'iflychat_time', '', time() - 3600, '/' );
	iflychat_token_destroy();
}

/**
 * Function to get Inbox.
 *
 * @since 4.7.1
 * @return string $output messages content as string.
 */
function iflychat_get_inbox() {

	$data = array(
		'uid'     => iflychat_get_user_id(),
		'api_key' => iflychat_get_option( 'iflychat_api_key' ),
	);

	$options = array(
		'method'    => 'POST',
		'body'      => $data,
		'timeout'   => 15,
		'headers'   => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
		'sslverify' => false,
	);

	$result = wp_remote_head(
		iflychat_get_host( true ) . ':' . DRUPALCHAT_EXTERNAL_A_PORT . '/r/',
		$options
	);
	$output = '';
	if ( ! is_wp_error( $result ) && isset( $result['response']['code'] ) && 200 === $result['response']['code'] ) {
		$query          = json_decode( $result['body'] );
		$timezone_offet = iflychat_get_option( 'gmt_offset' );
		$date_format    = iflychat_get_option( 'date_format' );
		$time_format    = iflychat_get_option( 'time_format' );
		foreach ( $query as $record ) {
			$rt      = $record->timestamp + ( $timezone_offet * 3600 );
			$output .= '<div style="display:block;border-bottom: 1px solid #ccc; padding: 10px;"><div style="font-size:130%; display: inline;">' . $record->name . '</div><div style="float:right;color:#AAA; font-size: 70%;">' . date( "{$date_format} {$time_format}", $rt ) . '</div><div style="display: block; padding: 10px;">' . $record->message . '</div></div>';
		}
	}
	return $output;
}


/**
 * Function to get Message thread.
 *
 * @since 4.7.1
 * @param Array $atts attributes as Array.
 * @return string $output messages content as string.
 */
function iflychat_get_message_thread( $atts ) {

	extract(
		shortcode_atts(
			array(
				'room_id' => '0',
				'id'      => '0',
			),
			$atts
		)
	);

	if ( isset( $room_id[0] ) && ( 'c' === $room_id[0] ) && isset( $room_id[1] ) && ( '-' === $room_id[1] ) ) {
		$room_id = substr( $room_id, 2 );
	} elseif ( '0' !== $id ) {
		if ( ( 'c' === $id[0] ) && ( '-' === $id[1] ) ) {
			$room_id = substr( $id, 2 );
		} else {
			$room_id = $id;
		}
	}

	$data = array(
		'uid1'    => iflychat_get_user_id(),
		'uid2'    => ( 'c-' . $room_id ),
		'api_key' => iflychat_get_option( 'iflychat_api_key' ),
	);

	$options = array(
		'method'    => 'POST',
		'body'      => $data,
		'timeout'   => 15,
		'headers'   => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
		'sslverify' => false,
	);

	$result = wp_remote_head(
		iflychat_get_host( true ) . ':' . DRUPALCHAT_EXTERNAL_A_PORT . '/q/',
		$options
	);

	$output = '';

	if ( ! is_wp_error( $result ) && isset( $result['response']['code'] ) && 200 === $result['response']['code'] ) {
		$query          = json_decode( $result['body'] );
		$timezone_offet = iflychat_get_option( 'gmt_offset' );
		$date_format    = iflychat_get_option( 'date_format' );
		$time_format    = iflychat_get_option( 'time_format' );
		foreach ( $query as $record ) {
			$rt      = $record->timestamp + ( $timezone_offet * 3600 );
			$output .= '<div style="display:block;border-bottom: 1px solid #ccc; padding: 1% 0% 1% 0%;"></div><div style="display:block; padding-top: 1%; padding-bottom: 0%"><div style="font-size:100%; display: inline;"><a href="#">' . $record->from_name . '</a></div><div style="float:right;font-size: 70%;">' . date( "{$date_format} {$time_format}", $rt ) . '</div><div style="display: block; padding-top: 1%; padding-bottom: 0%">' . $record->message . '</div></div>';
		}
	}
	return $output;
}

/**
 * Function to get Embed code.
 *
 * @since 4.7.1
 * @param Array $atts attributes as Array.
 * @return string $output messages content as string.
 */
function iflychat_get_embed_code( $atts ) {

	global $iflychat_engine;

	extract(
		shortcode_atts(
			array(
				'room_id'         => '0',
				'id'              => '0',
				'hide_user_list'  => 'no',
				'hide_popup_chat' => 'no',
				'height'          => '550px',
			),
			$atts
		)
	);

	$output = '';

	if ( $iflychat_engine ) {

		$output = '<style>.drupalchat-embed-chatroom-content {height: ' . $height . ' !important;}';
		if ( 'yes' === $hide_user_list ) {
			$output .= '#drupalchat-embed-user-list {display:none !important;}.drupalchat-embed-chatroom-content {width:95% !important;}';
		}
		$output .= '</style>';
		$output .= '<script type="text/javascript">if(typeof(iflyembed) === "undefined") {iflyembed = {};iflyembed.settings = {};iflyembed.settings.ifly = {};}iflyembed.settings.ifly.embed = "1";iflyembed.settings.ifly.ur_hy = "1";iflyembed.settings.ifly.embed_msg = "Type your message here. Press Enter to send.";iflyembed.settings.ifly.embed_online_user_text = "Online Users";</script>';
		if ( isset( $room_id[0] ) && ( 'c' === $room_id[0] ) && isset( $room_id[1] ) && ( '-' === $room_id[1] ) ) {
			$room_id = substr( $room_id, 2 );
		} elseif ( '0' !== $id ) {
			if ( ( 'c' === $id[0] ) && ( '-' === $id[1] ) ) {
				$room_id = substr( $id, 2 );
			} else {
				$room_id = $id;
			}
		}
		$output .= '<div id="drupalchat-embed-chatroom-' . $room_id . '" class="drupalchat-embed-chatroom-container';
		if ( 'yes' === $hide_popup_chat ) {
			$output .= ' drupalchat-hide-popup-chat';
		}
		$output .= '"></div>';
	} elseif ( iflychat_check_chat_admin() ) {
		$output .= '<div style="background-color:#eee;color:red;padding:5px;">iFlyChat is NOT set to load on this page. Please check the path visibility settings on iFlyChat plugin settings page. In case of any query, please create a support ticket <a href="https://iflychat.com/contact" target="_blank">here</a>. This error message is shown only to chat admins.</div>';
	}
	return $output;
}


/**
 * Function to get Embed code.
 *
 * @since 4.7.1
 * @return string $url URL as string.
 */
function iflychat_get_user_pic_url() {
	$current_user = wp_get_current_user();
	$url          = 'http://www.gravatar.com/avatar/' . ( ( $current_user->ID ) ? ( md5( strtolower( $current_user->user_email ) ) ) : ( '00000000000000000000000000000000' ) ) . '?d=mm&size=24';
	$hook_url     = apply_filters( 'iflychat_get_user_avatar_url_filter', '', $current_user->ID );
	if ( ! empty( $hook_url ) ) {
		return $hook_url;
	}

	if ( function_exists( 'bp_core_fetch_avatar' ) && ( $current_user->ID > 0 ) ) {
		$url = iflychat_get_avatar_url_from_html(
			bp_core_fetch_avatar(
				array(
					'item_id' => iflychat_get_user_id(),
					'html'    => false,
				)
			)
		);

	} elseif ( function_exists( 'user_avatar_fetch_avatar' ) && ( $current_user->ID > 0 ) ) {
		$local_url = user_avatar_fetch_avatar(
			array(
				'html'    => false,
				'item_id' => $current_user->ID,
			),
		);

		if ( $local_url ) {
			$url = $local_url;
		}
	} elseif ( function_exists( 'userpro_profile_data' ) && ( $current_user->ID > 0 ) ) {
		$user_id = $current_user->ID;
		$url     = userpro_profile_data( 'profilepicture', $user_id );
	} elseif ( function_exists( 'um_get_avatar_url' ) && ( $current_user->ID > 0 ) ) {
		$user_id = $current_user->ID;
		$url     = um_get_avatar_url( get_avatar( $user_id, $size = 96 ) );
	} elseif ( function_exists( 'get_wp_user_avatar_src' ) && ( $current_user->ID > 0 ) ) {
		$url = get_wp_user_avatar_src( iflychat_get_user_id() );
	} elseif ( function_exists( 'get_simple_local_avatar' ) && ( $current_user->ID > 0 ) ) {
		$source = get_simple_local_avatar( iflychat_get_user_id() );
		$source = explode( 'src="', $source );
		if ( isset( $source[1] ) ) {
			$source = explode( '"', $source[1] );
		} else {
			$source = explode( "src='", $source[0] );
			if ( isset( $source[1] ) ) {
				$source = explode( "'", $source[1] );
			} else {
				$source[0] = 'http://www.gravatar.com/avatar/' . ( ( $current_user->ID ) ? ( md5( strtolower( $current_user->user_email ) ) ) : ( '00000000000000000000000000000000' ) ) . '?d=mm&size=24';
			}
		}
		$url = $source[0];
	} elseif ( $current_user->ID > 0 ) {
		if ( false && function_exists( 'get_avatar_url' ) ) {
			$url = get_avatar_url( iflychat_get_user_id() );
		} else {
			$url = iflychat_get_avatar_url_from_html( get_avatar( iflychat_get_user_id() ) );
		}
	}

	$pos = strpos( $url, ':' );
	if ( false !== $pos ) {
		$url = substr( $url, $pos + 1 );
	}
	return $url;
}


/**
 * Function to get user profile url.
 *
 * @since 4.7.1
 * @return string url as string.
 */
function iflychat_get_user_profile_url() {
	global $userpro;
	$current_user = wp_get_current_user();

	$upl      = 'javascript:void(0)';
	$hook_upl = apply_filters( 'iflychat_get_user_profile_url_filter', 'javascript:void(0)', $current_user->ID );
	if ( $hook_upl === $upl ) {
		if ( function_exists( 'bp_core_get_userlink' ) && ( $current_user->ID > 0 ) ) {
			$upl = bp_core_get_userlink( $current_user->ID, false, true );
		} elseif ( function_exists( 'um_user_profile_url' ) && ( $current_user->ID > 0 ) ) {
			$upl = um_user_profile_url( $current_user->ID, false, true );
		} elseif ( ( $current_user->ID > 0 ) && ( null !== $userpro ) ) {
			$upl = ( $userpro->permalink( $current_user->ID ) );
		}
		return $upl;
	} else {
		return $hook_upl;
	}
}

/**
 * Function to get option by name.
 *
 * @since 4.7.1
 * @param string $name as option name string.
 * @return string option value string.
 */
function iflychat_get_option( $name ) {
	if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return get_site_option( $name );
	} else {
		return get_option( $name );
	}
}

/**
 * Function to Add a new option.
 *
 * @since 4.7.1
 * @param string  $name as option name string.
 * @param string  $value as option value string.
 * @param string  $v2 as string (Optional) Description. Not used anymore default ''.
 * @param Boolean $v3 as true false.
 * @return Boolean option insert Boolean.
 */
function iflychat_add_option( $name, $value, $v2, $v3 ) {
	if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return add_site_option( $name, $value, $v2, $v3 );
	} else {
		return add_option( $name, $value, '', $v3 );
	}
}

/**
 * Function to update a option.
 *
 * @since 4.7.1
 * @param string $name as option name string.
 * @param string $value as option value string.
 * @return Boolean option update Boolean.
 */
function iflychat_update_option( $name, $value ) {
	if ( is_multisite() && is_plugin_active_for_network( plugin_basename( __FILE__ ) ) ) {
		return update_site_option( $name, $value );
	} else {
		return update_option( $name, $value );
	}
}

/**
 * Function to check user access.
 *
 * @since 4.7.1
 * @return Boolean Access true or false Boolean.
 */
function iflychat_check_access() {
	global $current_user;
	$flag = apply_filters( 'iflychat_check_access_filter', true, $current_user->ID );
	if ( true === $flag ) {
		return true;
	} else {
		return false;
	}
	exit;
}

/**
 * Function to get avtar url from html.
 *
 * @since 4.7.1
 * @param String $source html as String.
 * @return String avtar url as String.
 */
function iflychat_get_avatar_url_from_html( $source ) {
	$source = explode( 'src="', $source );
	if ( isset( $source[1] ) ) {
		$source = explode( '"', $source[1] );
	} else {
		$source = explode( "src='", $source[0] );
		if ( isset( $source[1] ) ) {
			$source = explode( "'", $source[1] );
		}
	}
	return $source[0];
}

/**
 * Function to return host name (url) .
 *
 * @since 4.7.1
 * @param Boolean $https is tru or false as boolean.
 * @return String url as String.
 */
function iflychat_get_host( $https = false ) {
	if ( '1' === iflychat_get_option( 'iflychat_show_admin_list' ) ) {
		if ( $https ) {
			return 'https://support1.iflychat.com';
		} else {
			return 'http://support1.iflychat.com';
		}
	} else {
		if ( $https ) {
			return DRUPALCHAT_EXTERNAL_A_HOST;
		} else {
			return DRUPALCHAT_EXTERNAL_HOST;
		}
	}
}

/**
 * Function to get string.
 *
 * @since 4.7.1
 * @param String $words as String.
 * @return String $final word as String.
 */
function iflychat_process_stop_word_list( $words ) {
	$new_arr = array_map( 'trim', explode( ',', $words ) );
	$final   = implode( ',', $new_arr );
	return $final;
}

/**
 * Function to check chat camp.
 *
 * @since 4.7.1
 * @return Boolean true or false as Boolean.
 */
function iflychat_chatcamp_check() {
	$app_id = iflychat_get_option( 'iflychat_app_id' );
	if ( ! empty( $app_id ) ) {
		if ( false === strpos( $app_id, '-' ) && 19 === strlen( $app_id ) ) {
			return true;
		}
	}
	return false;
}

/**
 * Function to add chatcamp userdata.
 *
 * @since 4.7.1
 * @param Array $data users data as Array.
 * @return Array $data users data as Array.
 */
function iflychat_chatcamp_process_user_data( $data ) {
	$data['x-api-key']          = $data['api_key'];
	$data['id']                 = $data['user_id'];
	$data['display_name']       = $data['user_name'];
	$data['avatar_url']         = $data['user_avatar_url'];
	$data['profile_url']        = $data['user_profile_url'];
	$data['check_access_token'] = true;
	$data['access_token']       = iflychat_get_hash_session();
	$data['metadata']           = array( 'cc_user_roles' => wp_json_encode( $data['user_roles'] ) );
	return $data;
}

/**
 * Function to check user update or not.
 *
 * @since 4.7.1
 * @param Array  $new users data as Array.
 * @param Object $old users data as Object.
 * @return Boolean $update true or false as Boolean.
 */
function iflychat_chatcamp_user_should_update( $new, $old ) {
	$update = false;
	if ( isset( $new['user_name'] ) && $new['user_name'] !== $old->display_name ) {
		$update = true;
	}

	if ( isset( $new['user_avatar_url'] ) && $new['user_avatar_url'] !== $old->avatar_url ) {
		$update = true;
	}

	if ( isset( $new['user_profile_url'] ) && $new['user_profile_url'] !== $old->profile_url ) {
		$update = true;
	}

	if ( isset( $new['user_roles'] ) && wp_json_encode( $new['user_roles'] ) !== $old->metadata->cc_user_roles ) {
		$update = true;
	}
	return $update;
}

?>
