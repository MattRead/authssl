<?php

class AuthSSL extends Plugin
{

	/**
	 *
	 **/
	public function filter_default_rewrite_rules( array $rules )
	{
		$rule = array();
		$rule['name'] = 'auth_ssl';
		$rule['parse_regex'] = '%^auth/ssl/?$%i';
		$rule['build_str'] = 'auth/ssl';
		$rule['handler'] = 'ActionHandler';
		$rule['action'] = 'auth_ssl';
		$rule['description'] = _t('Dispatches the SSL authentication mechanism.', 'authssl');

		$rules[] = $rule;
		return $rules;
	}

	/**
	 * handles the authentication after Web Server verifies certificate.
	 *
	 * @todo store name of certificate as cert_username and hash as cert_password
	 **/
	public function action_handler_auth_ssl( SuperGlobal $handler_vars )
	{
		if ( !$this->has_valid_cert() ) {
			Session::error(_t('Your Browser did not present a valid Certificate', 'authssl'));
			Utils::redirect(Site::get_url('login'));
		}
		if ( User::identify()->loggedin ) {
			Session::notice(_t('You are already Logged in.', 'authssl'));
			Utils::redirect(Site::get_url('admin'));
		}
		if ( $user = User::get_by_email($this->get_env('SSL_CLIENT_S_DN_Email')) && isset($user->info->ssl_cert) ) {
			$serial = $this->get_env('SSL_CLIENT_M_SERIAL') . $this->get_env('SSL_CLIENT_I_DN');
			if ( Utils::crypt($serial, $user->info->ssl_cert) ) {
				EventLog::log(
					_t(
						'Successful login by ssl for %s using certificate #%s',
						array( $user->username, $this->get_env('SSL_CLIENT_M_SERIAL')),
						'authssl'
					),
					'info', 'authentication', 'SSLAuth'
				);
				$user->remember();
				Session::notice(_t('Successful login with certificate #%s',
					array($this->get_env('SSL_CLIENT_M_SERIAL')),
					'authssl'));
				Utils::redirect(Site::get_url('admin'));
			}
		}
		Session::error('Login Error. Invalid User.');
		Utils::redirect(Site::get_url('login'));
	}

	/**
	 * Get environment variables even after rewrite from Apache.
	 * This is needed with mod_rewrite as the handshake happens before the rewrite.
	 **/
	public function get_env( $key, $prefix = 'REDIRECT_' )
	{
		if ( array_key_exists($key, $_SERVER) ) {
			return $_SERVER[$key];
		}
		if ( array_key_exists($prefix.$key, $_SERVER) ) {
			return $_SERVER[$prefix.$key];
		}
		return null;
	}

	/**
	 * Determines if the browser provided a valid SSL client certificate
	 *
	 * @todo check if certificate has expired
	 * @return boolean True if the client cert is there and is valid
	 */
	public function has_valid_cert()
	{
//Utils::debug($_SERVER);
//exit;
		if (   !$this->get_env('SSL_CLIENT_M_SERIAL')
			|| !$this->get_env('SSL_CLIENT_V_END')
			|| !$this->get_env('SSL_CLIENT_VERIFY')
			||  $this->get_env('SSL_CLIENT_VERIFY') !== 'SUCCESS'
			|| !$this->get_env('SSL_CLIENT_I_DN')
		) {
			return false;
		}

		if ( $this->get_env('SSL_CLIENT_V_REMAIN') <= 0 ) {
			return false;
		}

		return true;
	}

	/**
	 * add a link to the login screen to Auth with SSL
	 **/
	public function action_theme_loginform_controls()
	{
		echo '<p><a href="' . Site::get_url('habari') . '/auth/url">Authenticate with SSL</a></p>';
	}

	/**
	 *
	 **/
	public function action_form_user($form, $user)
	{
		if ($this->has_valid_cert()) {
			$hash = Utils::crypt($_SERVER['SSL_CLIENT_M_SERIAL'] . $_SERVER['SSL_CLIENT_I_DN']);
			$serial = $_SERVER['SSL_CLIENT_M_SERIAL'];
			$dn = $_SERVER['SSL_CLIENT_I_DN'];
			$name = $_SERVER['SSL_CLIENT_S_DN_CN'];
			$email = $_SERVER['SSL_CLIENT_S_DN_Email'];
			$options = array($hash => "<b>$name ($email)</b><small> [$serial] $dn</small>");
			$form->user_info->append('radio', 'ssl_cert', $user, 'ssl certificate', $options);
		}
	}
}

?>
