<?php
function authenticateCheck($options = array()){
	$session = \ProcessWire\wire('session');
	$user = \ProcessWire\wire('user');
	$users = \ProcessWire\wire('users');
	$pages = \ProcessWire\wire('pages');
	if($options['user_id']){
		$u = $users->get($options['user_id']);
		$options = array(
			'type' => 'user',
			'access_token' => $u->podio_oauth_access_token,
			'refresh_token' => $u->podio_oauth_refresh_token,
			'expires_in' => $u->podio_oauth_expires_in,
			'ref' => json_decode($u->podio_oauth_ref)
		);
	}
	if (array_key_exists($options['type'].'_'.$options['ref']->id, $session->podio)){
		// Check if oauth already exists in Podio Session
		if ($options['type'] == 'session'){$options['type'] = 'user';}
		$app_type = $options['app_type'];
		$authData = $session->podio[$options['type'].'_'.$options['ref']->id];
		Podio::$oauth->access_token = $authData['access_token'];
		Podio::$oauth->refresh_token = $authData['refresh_token'];
		Podio::$oauth->expires_in = $authData['expires_in'];
		Podio::$oauth->ref = $authData['ref'];
		return;
	} else {
		if ($options['type'] == 'user'){
			// Replace current Podio info with User info
			Podio::$oauth->access_token = $options['access_token'];
			Podio::$oauth->refresh_token = $options['refresh_token'];
			Podio::$oauth->expires_in = $options['expires_in'];
			Podio::$oauth->ref = $options['ref'];
		} elseif ($options['type'] == 'authorization_code'){
			// Authenticate Login
			$oauth_options = array('code' => $options['code'], 'redirect_uri' => $options['redirect_uri']);
		} elseif ($options['type'] == 'app'){
			// Check Existing App oauth
			$app_type = $options['app_type'];
			$org = $pages->get("template=podio-org,owner=$session->pw_primary_acct");
			$app = $pages->get("template=podio-app,podio_app_type=$app_type,has_parent=$org");
			if($app->podio_oauth_expires_in > time()){
				$ref = json_decode($app->podio_oauth_ref);
				$authObj = array();
				$authObj['access_token'] = $app->podio_oauth_access_token;
				$authObj['refresh_token'] = $app->podio_oauth_refresh_token;
				$authObj['expires_in'] = $app->podio_oauth_expires_in;
				$authObj['ref'] = json_decode($app->podio_oauth_ref);
				$podio = $session->podio;
				$podio[$authObj['ref']->type.'_'.$authObj['ref']->id] = $authObj;
				$session->podio = $podio;
				Podio::$oauth->access_token = $authObj['access_token'];
				Podio::$oauth->refresh_token = $authObj['refresh_token'];
				Podio::$oauth->expires_in = $authObj['expires_in'];
				Podio::$oauth->ref = $authObj['ref'];
				return;
			}
			// Authenticate as App
			$oauth_options = array('app_id' => $options['app_id'], 'app_token' => $options['app_token']);
		}
		try {
			// Attempt Authentication and Update Podio Session
			if($options['type'] != 'user'){
				Podio::authenticate($options['type'], $oauth_options);
				if($session->prospect_session_id && $options['type'] == 'code'){
					try {
						$podioUser = PodioUserStatus::get();
						$prospect = $pages->get("template=prospect,podio_user_id=,prospect_session_id=$session->prospect_session_id");
						if ($prospect->id){
							$prospect->of(false);
							$prospect->email = $podioUser->user->mail;
							$prospect->podio_user_id = $podioUser->user->user_id;
							$prospect->date = $podioUser->user->created_on->format("Y-m-d H:i:s");
							if(strtotime($podioUser->user->created_on->format("Y-m-d H:i:s")) > $prospect->created){
								$prospect->prospect_status = 'Matched';
							} else {
								$prospect->prospect_status = 'Registered';
							}
							$prospect->save();
							$prospect->of(true);
						}
					} catch (Exception $e) {
						\ProcessWire\wire('log')->save('errors', 'Prospect Failed: '.$session->prospect_session_id.' - '.$e->getMessage());
						return;
					}
				}
			}
			if($options['type'] == 'app'){
				$app->of(false);
				$app->podio_oauth_access_token = Podio::$oauth->access_token;
				$app->podio_oauth_refresh_token = Podio::$oauth->refresh_token;
				$app->podio_oauth_expires_in = date("Y-m-d H:i:s", time()+Podio::$oauth->expires_in);
				$app->podio_oauth_ref = json_encode(Podio::$oauth->ref);
				$app->save();
				$app->of(true);
			}
			$authObj = array();
			$authObj['access_token'] = Podio::$oauth->access_token;
			$authObj['refresh_token'] = Podio::$oauth->refresh_token;
			$authObj['expires_in'] = Podio::$oauth->expires_in;
			$authObj['ref'] = Podio::$oauth->ref;
			if(Podio::$oauth->ref->type && Podio::$oauth->ref->id){
				$podio = $session->podio;
				$podio[Podio::$oauth->ref->type.'_'.Podio::$oauth->ref->id] = $authObj;
				$session->podio = $podio;
			}
			return;
		} catch (Exception $e) {
			return array('error' => 'Podio '.$options['type']. 'authentication failed!<br>Error Details:'.$e->body['error_description']);
		}
	}
}
?>