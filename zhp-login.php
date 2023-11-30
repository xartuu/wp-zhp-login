<?php

/**
 * ZHP Login
 *
 * @package           ZHP Login
 * @author            Artur Kociszewski
 * @copyright         2023 Artur Kociszewski
 * @license           GPL-3.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       ZHP Login
 * Plugin URI:        https://github.com/xartuu/wp-zhp-login
 * Description:       Enables the Azure AD Single Sign On used by ZHP.
 * Version:           0.1.5
 * Author:            Artur Kociszewski
 * Author URI:        https://arturkociszewski.pl/
 * License:           GPL v3 or later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       zhp-login
 */

use function Env\env;
use Roots\WPConfig\Config;

defined('ABSPATH') or die('Sorry ;(');

// Fetches variables from `.env` file in case of custom instance (eg. Bedrock or Wordplate)
if (class_exists(Config::class) && function_exists('Env\env')) {
    env('ZHP_LOGIN_CLIENT_ID') === null || Config::define('ZHP_LOGIN_CLIENT_ID', env('ZHP_LOGIN_CLIENT_ID'));
    env('ZHP_LOGIN_TENANT_ID') === null || Config::define('ZHP_LOGIN_TENANT_ID', env('ZHP_LOGIN_TENANT_ID'));
    env('ZHP_LOGIN_CLIENT_SECRET') === null || Config::define('ZHP_LOGIN_CLIENT_SECRET', env('ZHP_LOGIN_CLIENT_SECRET'));

    env('ZHP_LOGIN_SKIP_LOGIN_FORM') === null || Config::define('ZHP_LOGIN_SKIP_LOGIN_FORM', env('ZHP_LOGIN_SKIP_LOGIN_FORM'));
    env('ZHP_LOGIN_DISABLE_PASSWORDS') === null || Config::define('ZHP_LOGIN_DISABLE_PASSWORDS', env('ZHP_LOGIN_DISABLE_PASSWORDS'));
    env('ZHP_LOGIN_POST_RESPONSE') === null || Config::define('ZHP_LOGIN_POST_RESPONSE', env('ZHP_LOGIN_POST_RESPONSE'));
    env('ZHP_LOGIN_MATCH_BY_EMAIL') === null || Config::define('ZHP_LOGIN_MATCH_BY_EMAIL', env('ZHP_LOGIN_MATCH_BY_EMAIL'));
    env('ZHP_LOGIN_CREATE_NEW_USER') === null || Config::define('ZHP_LOGIN_CREATE_NEW_USER', env('ZHP_LOGIN_CREATE_NEW_USER'));
    env('ZHP_LOGIN_NEW_USER_ROLE') === null || Config::define('ZHP_LOGIN_NEW_USER_ROLE', env('ZHP_LOGIN_NEW_USER_ROLE'));
    env('ZHP_LOGIN_FULL_EMAIL_AS_USERNAME') === null || Config::define('ZHP_LOGIN_FULL_EMAIL_AS_USERNAME', env('ZHP_LOGIN_FULL_EMAIL_AS_USERNAME'));
    env('ZHP_LOGIN_SYNC_USER_DATA') === null || Config::define('ZHP_LOGIN_SYNC_USER_DATA', env('ZHP_LOGIN_SYNC_USER_DATA'));
    env('ZHP_LOGIN_USER_DATA_TO_SYNC') === null || Config::define('ZHP_LOGIN_USER_DATA_TO_SYNC', env('ZHP_LOGIN_USER_DATA_TO_SYNC'));
    Config::apply();
}

// Defines default values
defined('ZHP_LOGIN_SKIP_LOGIN_FORM') || define('ZHP_LOGIN_SKIP_LOGIN_FORM', false);
defined('ZHP_LOGIN_DISABLE_PASSWORDS') || define('ZHP_LOGIN_DISABLE_PASSWORDS', false);
defined('ZHP_LOGIN_POST_RESPONSE') || define('ZHP_LOGIN_POST_RESPONSE', true);
defined('ZHP_LOGIN_MATCH_BY_EMAIL') || define('ZHP_LOGIN_MATCH_BY_EMAIL', false);
defined('ZHP_LOGIN_CREATE_NEW_USER') || define('ZHP_LOGIN_CREATE_NEW_USER', false);
defined('ZHP_LOGIN_NEW_USER_ROLE') || define('ZHP_LOGIN_NEW_USER_ROLE', 'subscriber');
defined('ZHP_LOGIN_FULL_EMAIL_AS_USERNAME') || define('ZHP_LOGIN_FULL_EMAIL_AS_USERNAME', false);
defined('ZHP_LOGIN_SYNC_USER_DATA') || define('ZHP_LOGIN_SYNC_USER_DATA', true);
define('ZHP_LOGIN_NEW_USER_DATA', [ 'user_login', 'user_nicename', 'user_url', 'user_email', 'display_name', 'nickname', 'first_name', 'last_name' ]);
defined('ZHP_LOGIN_USER_DATA_TO_SYNC') || define('ZHP_LOGIN_USER_DATA_TO_SYNC', [ 'user_url', 'user_email', 'display_name', 'first_name', 'last_name' ]);
if (is_string(ZHP_LOGIN_USER_DATA_TO_SYNC)) {
    define('ZHP_LOGIN_PARSED_USER_DATA_TO_SYNC', array_map('trim', explode(',', ZHP_LOGIN_USER_DATA_TO_SYNC)));
} else {
    define('ZHP_LOGIN_PARSED_USER_DATA_TO_SYNC', array_map('trim', ZHP_LOGIN_USER_DATA_TO_SYNC));
}

// If plugin is used as a mu-plugin, COOKIEHASH is not defined
defined('COOKIEHASH') || wp_cookie_constants();

class ZHPLogin
{

    static $instance = false;

    private $redirect_to_cookie = 'wp-redirect-to';

    private $nonce_cookie = 'wp-zhplogin-nonce-' . COOKIEHASH;

    private $callback_url;

    private $callback_path;

    public function __construct()
    {
        // If plugin is not configured, it will notify the administrators.
        if (!$this->is_configured()) {
            add_action('all_admin_notices', [ $this, 'not_configured_message' ]);
            return;
        }
        $this->callback_url  = wp_login_url();
        $this->callback_path = str_replace(home_url('', 'login_post'), '', $this->callback_url);

        // The authenticate Azure AD user
        add_filter('authenticate', [ $this, 'wp_authenticate_zhp' ], 1, 3);

        // Adds ZHP Login action
        add_action('login_form_zhplogin', [ $this, 'zhplogin_action' ]);

        // Adds login button to the login form
        add_action('login_form', [ $this, 'add_login_button' ]);

        // If set, the login form will be skipped and the user will be redirected to Azure AD login
        add_action('login_init', [ $this, 'skip_login_form' ], 20);

        // Redirects after login to original location
        add_filter('login_redirect', [ $this, 'redirect_after_login' ], 20, 3);

        // In general, disables passwords
        if (ZHP_LOGIN_DISABLE_PASSWORDS === true) {
            // Disables password reset
            add_filter('allow_password_reset', '__return_false');
            // Disables password change
            add_filter('show_password_fields', '__return_false');
            // Disables password authentication
            add_filter('wp_authenticate_user', fn() => new WP_Error('zhp_login_passwords_disabled', __('Wyłączono autoryzację hasłem, użyj swojego konta ZHP w celu zalogowania.', 'zhp-login')));
            // Disables application passwords
            add_filter('wp_is_application_passwords_available', '__return_false');
        }
    }

    // Gets the (only) instance of the plugin. Initializes an instance if it hasn't yet.
    public static function get_instance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // Checks if plugin is configured
    public function is_configured()
    {
        return defined('ZHP_LOGIN_CLIENT_ID') && defined('ZHP_LOGIN_TENANT_ID') && defined('ZHP_LOGIN_CLIENT_SECRET');
    }

    // Displays a message to the administrators that the plugin is not configured
    public function not_configured_message()
    {
        print(sprintf(
            '<div id="message" class="error"><p>%s</p></div>',
            __('ZHP Login: Plugin nie jest poprawnie skonfigurowany, sprawdź czy w pliku wp-config.php znajdują się ustawienia pluginu.', 'zhp-login')
        )
        );
    }

    // Returns the URL that redirects user to ZHP Login in Azure AD.
    public function zhplogin_url($redirect = '')
    {
        $args = [
            'action' => 'zhplogin',
         ];

        if (!empty($redirect)) {
            $args[ 'redirect_to' ] = urlencode($redirect);
        }

        if (is_multisite()) {
            $blog_details  = get_site();
            $wp_login_path = $blog_details->path . 'wp-login.php';
        } else {
            $wp_login_path = 'wp-login.php';
        }

        $zhplogin_url = add_query_arg($args, network_site_url($wp_login_path, 'login'));

        return apply_filters('zhplogin_url', $zhplogin_url, $redirect);
    }

    // Redirects user to ZHP Login in Azure AD.
    public function zhplogin_action()
    {
        // Save the redirect_to parameter
        if (!empty($_REQUEST[ 'redirect_to' ])) {
            $redirect_to = esc_url_raw($_REQUEST[ 'redirect_to' ]);
        } else {
            $redirect_to = admin_url();
        }

        // If user is already logged in, redirect him to the final destination
        if (is_user_logged_in()) {
            return wp_safe_redirect($redirect_to);
        }

        // Generate nonce and save it in the cookie
        $nonce_value = wp_generate_uuid4();
        setcookie($this->nonce_cookie, $nonce_value, time() + 60 * 5, $this->callback_path, COOKIE_DOMAIN, is_ssl(), true);

        if ($redirect_to !== admin_url()) {
            setcookie($this->redirect_to_cookie, $redirect_to, time() + 60 * 5, wp_login_url(), COOKIE_DOMAIN, is_ssl(), true);
        }

        $login_url = 'https://login.microsoftonline.com/' . urlencode(ZHP_LOGIN_TENANT_ID) . '/oauth2/v2.0/authorize?' . http_build_query([
            'client_id'     => ZHP_LOGIN_CLIENT_ID,
            'scope'         => 'https://graph.microsoft.com/User.Read',
            'response_type' => 'code',
            'redirect_uri'  => $this->callback_url,
            'response_mode' => ZHP_LOGIN_POST_RESPONSE === true ? 'form_post' : 'query',
            'state'         => $nonce_value,
         ]);

        return wp_redirect($login_url);
    }

    // Adds login button to the login form
    public function add_login_button()
    {
        $zhplogin_url = $this->zhplogin_url(@$_REQUEST[ 'redirect_to' ]);
        print(sprintf(
            '
<p style="text-align: center; padding-top: 15px; padding-bottom: 30px;">
    <a href="%s">
        <object style="height: 2em; width: 2em; top: .5em; position: relative; margin-right: 0.5em;" type="image/svg+xml" data="%s"></object>
        %s
    </a>
</p>',
            $zhplogin_url,
            plugins_url('/assets/img/logo_zhp_zielone.svg', __FILE__),
            __('Zaloguj się korzystając z konta ZHP', 'zhp-login'),
        )
        );
    }

    // If set, the login form will be skipped and the user will be redirected to Azure AD login
    public function skip_login_form()
    {
        // Skip login form if enabled
        if (ZHP_LOGIN_SKIP_LOGIN_FORM !== true) {
            return;
        }

        // User just logged out
        if (!empty($_REQUEST[ 'loggedout' ]) || !empty($_POST[ 'log' ])) {
            return;
        }

        // Get the parameters from the request
        $params = ZHP_LOGIN_POST_RESPONSE === true ? $_POST : $_GET;

        // User is logging in with ZHP
        if (!empty($params[ 'error' ]) || !empty($params[ 'code' ])) {
            return;
        }

        // Redirect to ZHP Login
        return wp_redirect($this->zhplogin_url(@$_REQUEST[ 'redirect_to' ]));
    }

    // Redirects after login to original location
    public function redirect_after_login($redirect_to, $request, $user)
    {
        if (is_a($user, 'WP_User') && !empty($_COOKIE[ 'wp-redirect-to' ])) {
            $redirect_to = $_COOKIE[ 'wp-redirect-to' ];
            setcookie($this->redirect_to_cookie, '', time() + 60 * 5, wp_login_url(), COOKIE_DOMAIN, is_ssl(), true);
            unset($_COOKIE[ 'wp-redirect-to' ]);
        }

        return $redirect_to;
    }

    // Generate unique username from email
    public function generate_username($email, $user_login = '')
    {
        $email    = str_replace('_', '-', $email);
        $parts    = explode('@', $email);
        $username = $parts[ 0 ];
        $username = str_replace('.', '-', $username);
        $domain   = $parts[ 1 ];

        // If domain is part of ZHP domains, username will be generated from domain
        if (ZHP_LOGIN_FULL_EMAIL_AS_USERNAME !== true) {
            // firstname-lastname@zhp.net.pl -> firstname-lastname-net
            if ($domain == 'zhp.net.pl') {
                $username .= '-net';
            } elseif (substr($domain, -7) == '.zhp.pl') {
                // firstname-lastname@*.zhp.pl -> firstname-lastname-*
                $username .= '-' . str_replace('.zhp.pl', '', $domain);
            } else {
                // firstname-lastname@zhp.pl -> firstname-lastname
                $username = $username;
            }
        } else {
            // name@domain.tld -> name-domain-tld
            $username = $username . '-' . str_replace('.', '-', $domain);
        }

        $username = sanitize_user($username, true);

        // Check if username exists, if current user's username, return false
        $username_check = function ($username) use ($user_login) {
            if (empty($user_login)) {
                return username_exists($username);
            }

            $user = get_user_by('login', $username);
            return !empty($user) && $user->user_login != $user_login;
        };

        // Generate unique username by addying suffix
        $suffix = 2;
        while ($username_check($alt_username ?? $username)) {
            $base_length  = 49 - mb_strlen($suffix);
            $alt_username = mb_substr($username, 0, $base_length) . "-$suffix";
            ++$suffix;
        }
        $username = $alt_username ?? $username;

        return $username;
    }

    // Get sync user data from Azure AD to WordPress
    public function get_sync_user_data($zhp_user_data, $username, $new_user = false)
    {
        $user_data    = [  ];
        $data_to_sync = ZHP_LOGIN_PARSED_USER_DATA_TO_SYNC;

        if ($new_user === true) {
            $data_to_sync = ZHP_LOGIN_NEW_USER_DATA;
        }

        // wp_update_user() does not update user_login, so we are doing that after calling wp_update_user(), here for new users
        if (in_array('user_login', $data_to_sync)) {
            $user_data[ 'user_login' ] = $username;
        }

        if (in_array('user_nicename', $data_to_sync)) {
            $user_data[ 'user_nicename' ] = sanitize_title($username);
        }

        if (in_array('user_url', $data_to_sync)) {
            $user_data[ 'user_url' ] = 'https://eur.delve.office.com/?' . http_build_query([
                'u' => urlencode($zhp_user_data->id),
                'v' => 'work',
             ]);
        }

        if (in_array('user_email', $data_to_sync)) {
            $user_data[ 'user_email' ] = $zhp_user_data->userPrincipalName;
        }

        if (in_array('display_name', $data_to_sync)) {
            $user_data[ 'display_name' ] = !empty($zhp_user_data->displayName) ? $zhp_user_data->displayName : '';
        }

        if (in_array('nickname', $data_to_sync)) {
            $user_data[ 'nickname' ] = $username;
        }

        if (in_array('first_name', $data_to_sync)) {
            $user_data[ 'first_name' ] = !empty($zhp_user_data->givenName) ? $zhp_user_data->givenName : '';
        }

        if (in_array('last_name', $data_to_sync)) {
            $user_data[ 'last_name' ] = !empty($zhp_user_data->surname) ? $zhp_user_data->surname : '';
        }

        return $user_data;
    }

    // Authenticate Azure AD user
    public function wp_authenticate_zhp($user, $username, $password)
    {
        global $wpdb;

        // Do not authorize when the user is already logged in
        if ($user instanceof WP_User) {
            return $user;
        }

        // Get the parameters from the request
        $params = ZHP_LOGIN_POST_RESPONSE === true ? $_POST : $_GET;

        // The attempt to get an authorization code failed.
        if (!empty($params[ 'error' ])) { // NOTE: Is this necessary?
            return new WP_Error(
                $params[ 'error' ],
                sprintf(
                    __('Błąd Microsoft Graph: %s', 'zhp-login'),
                    $params[ 'error_description' ]
                )
            );
        }

        // Listens for callback from Azure AD
        if (empty($params[ 'code' ])) {
            return $user;
        }

        // Check if the session is valid
        if (empty($_COOKIE[ $this->nonce_cookie ])) {
            return new WP_Error(
                'missing_zhplogin_nonce',
                __('Błąd: Użytkownik nie posiada odpowiedniego identyfikatora nonce. Zaloguj się ponownie.', 'zhp-login')
            );
        }

        // Delete the nonce cookie
        $nonce_value = $_COOKIE[ $this->nonce_cookie ];
        setcookie($this->nonce_cookie, '', time(), $this->callback_path, COOKIE_DOMAIN, is_ssl(), true);

        // Check if there is no forgery
        if (empty($params[ 'state' ]) || $params[ 'state' ] != $nonce_value) {
            return new WP_Error(
                'zhplogin_nonce_mismatch',
                sprintf(__('Błąd: Niezgodny identyfikator nonce, oczekiwano: %s', 'zhp-login'), $nonce_value)
            );
        }

        // Get the access token request
        $token_response = wp_remote_post('https://login.microsoftonline.com/' . urlencode(ZHP_LOGIN_TENANT_ID) . '/oauth2/v2.0/token', [
            'body' => [
                'client_id'     => ZHP_LOGIN_CLIENT_ID,
                'client_secret' => ZHP_LOGIN_CLIENT_SECRET,
                'scope'         => 'https://graph.microsoft.com/User.Read',
                'redirect_uri'  => $this->callback_url,
                'grant_type'    => 'authorization_code',
                'code'          => $params[ 'code' ],
             ],
         ]);

        // Failed coused by wp error
        if (is_wp_error($token_response)) {
            return new WP_Error($token_response->get_error_code(), $token_response->get_error_message());
        }

        // Parse access token
        $token_data = json_decode(wp_remote_retrieve_body($token_response));

        // Failed to obtain access token despite authorization code
        if (!empty($token_data->error)) {
            return new WP_Error(
                $token_data->error,
                sprintf(
                    __('Błąd przy prośbie o token: %s', 'zhp-login'),
                    $token_data->error_description
                )
            );
        }

        // It's not clear what happened
        if (empty($token_data->access_token)) {
            return new WP_Error('unknown', __('Błąd: Nie uzyskano tokenu dostępu z niewiadomego powodu.', 'zhp-login'));
        }

        // Get user data from Azure AD request
        $user_response = wp_remote_get('https://graph.microsoft.com/v1.0/me', [
            'headers' => [
                'Authorization' => $token_data->token_type . " " . $token_data->access_token,
             ],
         ]);

        // Failed coused by wp error
        if (is_wp_error($user_response)) {
            return new WP_Error($user_response->get_error_code(), $user_response->get_error_message());
        }

        // Parse user data
        $zhp_user_data = json_decode(wp_remote_retrieve_body($user_response));

        // Failed to obtain user informations
        if (!empty($zhp_user_data->error)) {
            return new WP_Error(
                $zhp_user_data->error->code,
                sprintf(
                    __('Błąd przy pobieraniu informacji o użytkowniku: %s', 'zhp-login'),
                    $zhp_user_data->error->message
                )
            );
        }

        // Check if Azure AD provided user id
        if (empty($zhp_user_data->id)) {
            return new WP_Error(
                'zhp_login_no_id',
                __('Błąd: Nie znaleziono identyfikatora użytkownika ZHP.', 'zhp-login')
            );
        }

        // Check if Azure AD provided user email address
        if (empty($zhp_user_data->userPrincipalName) || !is_email($zhp_user_data->userPrincipalName)) {
            return new WP_Error(
                'zhp_login_no_email',
                __('Błąd: Nie otrzymanu adresu e-mail ZHP od usługi Azure AD.', 'zhp-login')
            );
        }

        // Define Azure AD user data
        $email  = $zhp_user_data->userPrincipalName;
        $zhp_id = $zhp_user_data->id;

        // Get user by metadata zhp_id
        $users = get_users([
            'meta_key'   => 'zhp_id',
            'meta_value' => $zhp_id,
         ]);

        // NOTE: Scenario if metadata zhp_id points to no longer existing user, will be ignored in $users array
        switch (count($users)) {

            // User found, proceed to login
            case 1:
                $user = $users[ 0 ];
                break;

            // No user found
            case 0:
                if (ZHP_LOGIN_MATCH_BY_EMAIL !== true && ZHP_LOGIN_CREATE_NEW_USER !== true) {
                    return new WP_Error(
                        'zhp_login_no_user',
                        __('Błąd: Nie znaleziono użytkownika WordPress pasującego do identyfikatora ZHP.', 'zhp-login')
                    );
                }

                // Find user by email
                if (ZHP_LOGIN_MATCH_BY_EMAIL === true) {
                    // Search for user by email
                    $user = get_user_by('email', $email);

                    // User found, proceed to login
                    if (!empty($user)) {
                        break;
                    }
                }

                // User still not found even by email and creation of new users is disabled
                if (ZHP_LOGIN_CREATE_NEW_USER !== true && empty($user)) {
                    return new WP_Error(
                        'zhp_login_no_user_by_email',
                        sprintf(
                            __('Błąd: Nie znaleziono użytkownika WordPress pasującego do adresu e-mail %s.', 'zhp-login'),
                            $email
                        )
                    );
                }

                // Check if user with this email exists
                if (email_exists($email)) {
                    return new WP_Error(
                        'zhp_login_email_exists',
                        sprintf(
                            __('Błąd: Nie udało się zarejestrować, użytkownik o adresie e-mail %s już istnieje.', 'zhp-login'),
                            $email
                        )
                    );
                }

                // Set user data for new user, proceed to create new user
                $user_data = array_merge($this->get_sync_user_data($zhp_user_data, $this->generate_username($email), true), [
                    'user_pass' => wp_generate_password(64, true),
                    'role'      => ZHP_LOGIN_NEW_USER_ROLE,
                 ]);

                // Create new user
                $user_id = wp_insert_user($user_data);

                // Failed to create new user
                if (is_wp_error($user_id)) {
                    return new WP_Error(
                        'user_not_registered',
                        sprintf(
                            __('Błąd: Nie udało stworzyć się nowego konta dla użytkownika o adresie e-mail %s.', 'zhp-login'),
                            $email
                        )
                    );
                }

                // Proceed to login
                $user = new WP_User($user_id);
                break;

            // More than one user found
            default:
                return new WP_Error(
                    'zhp_login_multiple_users',
                    __('Błąd: Znaleziono więcej niż jednego użytkownika WordPress o tym samym identyfikatorze ZHP.', 'zhp-login')
                );
                break;
        }

        // Add zhp_id metadata to user for future logins
        if (get_user_meta($user->ID, 'zhp_id', true) !== $zhp_id) {
            update_user_meta($user->ID, 'zhp_id', $zhp_id);
        }

        // Update user data
        if (ZHP_LOGIN_SYNC_USER_DATA === true) {
            $username = $this->generate_username($email, $user->user_login);

            $sync_user_data = $this->get_sync_user_data($zhp_user_data, $username);
            wp_update_user(array_merge($sync_user_data, [
                'ID' => $user->ID,
             ]));

            // wp_update_user() does not update user_login, so we have to do it manually
            if (in_array('user_login', ZHP_LOGIN_PARSED_USER_DATA_TO_SYNC)) {
                if (!username_exists($username)) {
                    $wpdb->update(
                        $wpdb->users,
                        [ 'user_login' => $username ],
                        [ 'ID' => $user->ID ]
                    );
                }
            }

        }

        return $user;
    }
}

// Initializes the plugin
ZHPLogin::get_instance();
