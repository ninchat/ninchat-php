<?php

require_once 'Ninchat/Master.php';

$master_key_id = '22nlihvg';
$master_key_secret = 'C58sAn+Dp2Ogb2+FdfSNg3J0ImMYfYodUUgXFF2OPo0=';
$expire = time() + 60;
$user_id = '22ouqqbp';
$channel_id = '1bfbr0u';
$member_attrs = array(
	array('silenced', FALSE),
);
$metadata = array(
	'foo' => 3.14159,
	'bar' => 'asdf',
	'baz' => array(1, 2, 3),
	'quux' => array(
		'a' => 100,
		'b' => 200,
	),
);

function dump($str)
{
	echo "\n";
	echo 'Size: ' . strlen($str) . "\n";
	echo 'Data: ' . $str . "\n";
}

$master = new Ninchat\Master($master_key_id, $master_key_secret);

dump($master->sign_create_session($expire));
dump($master->sign_create_session_for_user($expire, $user_id));
dump($master->sign_join_channel($expire, $channel_id));
dump($master->sign_join_channel($expire, $channel_id, $member_attrs));
dump($master->sign_join_channel_for_user($expire, $channel_id, $user_id));
dump($master->sign_join_channel_for_user($expire, $channel_id, $user_id, $member_attrs));

dump($master->secure_metadata($expire, $metadata));
dump($master->secure_metadata_for_user($expire, $metadata, $user_id));
