<?php
$signature = $_SERVER['HTTP_X_HUB_SIGNATURE'];
if ($signature) {
	$data = file_get_contents('php://input');
	$postdat = json_decode($data);
	$hash = "sha1=".hash_hmac('sha1', $data, GIT_SECRET);
	if (strcmp($signature, $hash) == 0) {
		if($postdat->action == 'closed' && $postdat->pull_request->merged){
			$commands = array(
				'echo $PWD',
				'whoami',
				'git reset --hard HEAD',
				'git pull origin',
				'git status',
				'git submodule sync',
				'git submodule update',
				'git submodule status',
			);
			$output = '';
			foreach($commands AS $command){
				$tmp = shell_exec($command);
				$output .= '$'.$command.': '.html_entity_decode(trim($tmp))."\n";
			}
			echo $output;
			exit;
		} else {
			exit;
		} 
	}
}
http_response_code(404);
?>