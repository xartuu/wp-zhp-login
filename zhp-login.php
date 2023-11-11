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
 * Version:           0.1.0
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
    env('ZHP_LOGIN_POST_RESPONSE') === null || Config::define('ZHP_LOGIN_POST_RESPONSE', env('ZHP_LOGIN_POST_RESPONSE'));
    env('ZHP_LOGIN_DISABLE_PASSWORDS') === null || Config::define('ZHP_LOGIN_DISABLE_PASSWORDS', env('ZHP_LOGIN_DISABLE_PASSWORDS'));
    env('ZHP_LOGIN_SKIP_LOGIN_FORM') === null || Config::define('ZHP_LOGIN_SKIP_LOGIN_FORM', env('ZHP_LOGIN_SKIP_LOGIN_FORM'));
    env('ZHP_LOGIN_CREATE_NEW_USER') === null || Config::define('ZHP_LOGIN_CREATE_NEW_USER', env('ZHP_LOGIN_CREATE_NEW_USER'));
    env('ZHP_LOGIN_NEW_USER_ROLE') === null || Config::define('ZHP_LOGIN_NEW_USER_ROLE', env('ZHP_LOGIN_NEW_USER_ROLE'));
    Config::apply();
}

// Defines default values
defined('ZHP_LOGIN_POST_RESPONSE') || define('ZHP_LOGIN_POST_RESPONSE', false);
defined('ZHP_LOGIN_DISABLE_PASSWORDS') || define('ZHP_LOGIN_DISABLE_PASSWORDS', false);
defined('ZHP_LOGIN_SKIP_LOGIN_FORM') || define('ZHP_LOGIN_SKIP_LOGIN_FORM', false);
defined('ZHP_LOGIN_CREATE_NEW_USER') || define('ZHP_LOGIN_CREATE_NEW_USER', false);
defined('ZHP_LOGIN_NEW_USER_ROLE') || define('ZHP_LOGIN_NEW_USER_ROLE', 'subscriber');

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
        if (!$this->isConfigured()) {
            add_action('all_admin_notices', array($this, 'not_configured_message'));
            return;
        }
        $this->callback_url  = wp_login_url();
        $this->callback_path = str_replace(home_url('', 'login_post'), '', $this->callback_url);

        // The authenticate Azure AD user
        add_filter('authenticate', array($this, 'authenticate'), 1, 3);

        // Adds ZHP Login action
        add_action('login_form_zhplogin', array($this, 'zhplogin_action'));

        // Adds login button to the login form
        add_action('login_form', array($this, 'add_login_button'));

        // If set, the login form will be skipped and the user will be redirected to Azure AD login
        add_action('login_init', array($this, 'skip_login_form'), 20);

        // Redirects after login to original location
        add_filter('login_redirect', array($this, 'redirect_after_login'), 20, 3);

        // In general, disables passwords
        if (defined('ZHP_LOGIN_DISABLE_PASSWORDS') && ZHP_LOGIN_DISABLE_PASSWORDS === true) {
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
    public static function getInstance()
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // Checks if plugin is configured
    public function isConfigured()
    {
        return defined('ZHP_LOGIN_CLIENT_ID') && defined('ZHP_LOGIN_TENANT_ID') && defined('ZHP_LOGIN_CLIENT_SECRET');
    }

    // Displays a message to the administrators that the plugin is not configured
    public function notConfiguredMessage()
    {
        print(sprintf(
            '<div id="message" class="error"><p>%s</p></div>',
            __('ZHP Login: Plugin nie jest poprawnie skonfigurowany, sprawdź czy w pliku wp-config.php znajdują się ustawienia pluginu.', 'zhp-login')
        )
        );
    }

    // Returns the URL that redirects user to ZHP Login in Azure AD.
    public function zhploginUrl($redirect = '')
    {
        $args = array(
            'action' => 'zhplogin',
        );

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

    // zhp_login_action
    public function zhploginAction()
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
    public function addLoginButton()
    {
        $zhplogin_url = $this->zhploginUrl(@$_REQUEST[ 'redirect_to' ]);
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
    public function skipLoginForm()
    {
        if (ZHP_LOGIN_SKIP_LOGIN_FORM !== true) {
            return;
        }

        if (!empty($_REQUEST[ 'loggedout' ]) || !empty($_POST[ 'log' ])) {
            return;
        }

        return wp_redirect($this->zhploginUrl(@$_REQUEST[ 'redirect_to' ]));
    }

    // Redirects after login to original location
    public function redirectAfterLogin($redirect_to, $request, $user)
    {
        if (is_a($user, 'WP_User') && !empty($_COOKIE[ 'wp-redirect-to' ])) {
            $redirect_to = $_COOKIE[ 'wp-redirect-to' ];
            setcookie($this->redirect_to_cookie, '', time() + 60 * 5, wp_login_url(), COOKIE_DOMAIN, is_ssl(), true);
            unset($_COOKIE[ 'wp-redirect-to' ]);
        }

        return $redirect_to;
    }

    // Listens for callback from Azure AD
    public function authenticate($user, $username, $password)
    {
        // Do not authorize when the user is already logged in
        if (is_a($user, 'WP_User')) {
            return $user;
        }

        // Get the parameters from the request
        if (ZHP_LOGIN_POST_RESPONSE === true && $_SERVER[ 'REQUEST_METHOD' ] === 'POST') {
            parse_str(file_get_contents('php://input'), $params);
        } else {
            parse_str($_SERVER[ 'QUERY_STRING' ], $params);
        }

        // The attempt to get an authorization code failed.
        if (!empty($params[ 'error' ])) {
            return new WP_Error(
                $params[ 'error' ],
                sprintf(
                    __('Błąd Microsoft Graph: %s', 'zhp-login'),
                    $params[ 'error_description' ]
                )
            );
        }

        if (empty($params[ 'code' ])) {
            return;
        }

        // Check if the session is valid
        if (empty($_COOKIE[ $this->nonce_cookie ])) {
            return new WP_Error(
                'missing_zhplogin_nonce',
                __('Błąd: Użytkownik nie posiada odpowiedniego identyfikatora nonce. Odśwież stronę i spróbuj ponownie.', 'zhp-login')
            );
        }

        // Check if there is no forgery
        $nonce_value = $_COOKIE[ $this->nonce_cookie ];
        setcookie($this->nonce_cookie, $nonce_value, time(), $this->callback_path, COOKIE_DOMAIN, is_ssl(), true);

        if (empty($params[ 'state' ]) || $params[ 'state' ] != $nonce_value) {
            return new WP_Error(
                'zhplogin_nonce_mismatch',
                sprintf(__('Błąd: Niezgodny identyfikator nonce, oczekiwano: %s', 'zhp-login'), $nonce_value)
            );
        }

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

        $user_response = wp_remote_get('https://graph.microsoft.com/v1.0/me', [
            'headers' => [
                'Authorization' => '$token_data->token_type $token_data->access_token',
             ],
         ]);

        // Failed coused by wp error
        if (is_wp_error($user_response)) {
            return new WP_Error($user_response->get_error_code(), $user_response->get_error_message());
        }

        $user_data = json_decode(wp_remote_retrieve_body($user_response));

        // Failed to obtain user informations
        if (!empty($user_data->error)) {
            return new WP_Error(
                $user_data->error,
                sprintf(
                    __('Błąd przy pobieraniu informacji o użytkowniku: %s', 'zhp-login'),
                    $user_data->error_description
                )
            );
        }

        if (!empty($user_data->userPrincipalName) && is_string($user_data->userPrincipalName)) {
            $email = $user_data->userPrincipalName;
        } elseif (!empty($user_data->mail) && is_string($user_data->mail)) {
            $email = $user_data->mail;
        } else {
            // Azure AD response contains neither the email address nor the userPrincipalName
            return new WP_Error(
                'zhp_login_no_email',
                __('Błąd: Nie znaleziono informacji o użytkowniku ZHP.', 'zhp-login')
            );
        }

        $user = get_user_by('email', $email);

        if (!is_a($user, 'WP_User')) {
            if (ZHP_LOGIN_CREATE_NEW_USER !== true) {
                // User does not exist
                return new WP_Error(
                    'zhp_login_no_user',
                    sprintf(
                        __('Błąd: Użytkownik o adresie e-mail %s nie instnieje.', 'zhp-login'),
                        $email
                    )
                );
            } else {
                // Create new user if it does not exist
                $new_user_data = array(
                    'user_email'   => $email,
                    'user_login'   => $email,
                    'display_name' => !empty($user_data->displayName) ? $user_data->displayName : '',
                    'first_name'   => !empty($user_data->givenName) ? $user_data->givenName : '',
                    'last_name'    => !empty($user_data->surname) ? $user_data->surname : '',
                    'user_pass'    => wp_generate_password(64, true, true),
                    'role'         => ZHP_LOGIN_NEW_USER_ROLE,
                );

                $new_user_id = wp_insert_user($new_user_data);

                // Failed to create new user
                if (is_wp_error($new_user_id)) {
                    return new WP_Error(
                        'user_not_registered',
                        sprintf(
                            __('Błąd: Nie udało stworzyć się nowego użytkownika o adresie e-mail %s.', 'zhp-login'),
                            $email
                        )
                    );
                }

                $user = new WP_User($new_user_id);
            }
        }

        return $user;
    }
}

// Initializes the plugin
ZHPLogin::getInstance();
