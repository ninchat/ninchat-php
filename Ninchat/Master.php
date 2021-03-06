<?php

/*
 * Copyright (c) 2013, Somia Reality Oy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace Ninchat;

use \Exception;

/**
 * Ninchat master key utilities.
 *
 * The master key id and secret may be obtained with the create_master_key
 * Ninchat API action (not supported by this library).  The sign_* methods
 * create values for the master_sign API parameters, and the secure_* methods
 * create values for the "secure" property of the audience_metadata API
 * parameter.
 *
 * The signatures and secured metadata may be used once before the expiration
 * time.  Expiration time is specified in Unix time (seconds since 1970-01-01
 * UTC), and may not be more than one week in the future.
 */
class Master
{
	/**
	 * @var string
	 */
	private $key_id;

	/**
	 * @var string
	 */
	private $key_secret_bin;

	/**
	 * @param string  $key_id
	 * @param string  $key_secret
	 * @throws Exception
	 */
	public function __construct($key_id, $key_secret)
	{
		$this->key_id = $key_id;
		$this->key_secret_bin = base64_decode($key_secret);
		if (!$this->key_secret_bin)
			throw new Exception('Ninchat master key is invalid');
	}

	/**
	 * Generate a signature for use with a create_session API call, when
	 * creating a new user.  The created user will become a puppet of the
	 * master.
	 *
	 * @param integer|float  $expire
	 * @return string
	 * @throws Exception
	 */
	public function sign_create_session($expire)
	{
		$msg = array(
			array('action', 'create_session'),
		);

		return $this->sign($expire, $msg);
	}

	/**
	 * Generate a signature for use with a create_session API call, when
	 * authenticating an existing user.  The user must be a puppet of the
	 * master.
	 *
	 * The user_id specified here must be repeated in the API call.
	 *
	 * @param integer|float  $expire
	 * @param string         $user_id
	 * @return string
	 * @throws Exception
	 */
	public function sign_create_session_for_user($expire, $user_id)
	{
		$msg = array(
			array('action', 'create_session'),
			array('user_id', $user_id),
		);

		return $this->sign($expire, $msg);
	}

	/**
	 * Generate a signature for use with a join_channel API call.  The
	 * master must own the channel.
	 *
	 * The channel_id and member_attrs specified here must be repeated in
	 * the API call.
	 *
	 * The member_attrs array will be sorted.
	 *
	 * @param integer|float  $expire
	 * @param string         $channel_id
	 * @param array|null     $member_attrs (list of pairs)
	 * @return string
	 * @throws Exception
	 */
	public function sign_join_channel($expire, $channel_id, $member_attrs = NULL)
	{
		return $this->sign_join_channel_for_user($expire, $channel_id, NULL, $member_attrs);
	}

	/**
	 * Generate a signature for use with a join_channel API call, by the
	 * specified user only.  The master must own the channel.
	 *
	 * The channel_id and member_attrs specified here must be repeated in
	 * the API call.
	 *
	 * The member_attrs array will be sorted.
	 *
	 * @param integer|float  $expire
	 * @param string         $channel_id
	 * @param string         $user_id
	 * @param array|null     $member_attrs (list of pairs)
	 * @return string
	 * @throws Exception
	 */
	public function sign_join_channel_for_user($expire, $channel_id, $user_id, $member_attrs = NULL)
	{
		$suffix = '';

		$msg = array(
			array('action', 'join_channel'),
			array('channel_id', $channel_id),
		);

		if ($user_id !== NULL) {
			$msg[] = array('user_id', $user_id);
			$suffix = '1';
		}

		if ($member_attrs) {
			sort($member_attrs);
			$msg[] = array('member_attrs', $member_attrs);
		}

		return $this->sign($expire, $msg, $suffix);
	}

	/**
	 * @param integer|float  $expire
	 * @param array          $msg
	 * @param string         $suffix
	 * @return string
	 * @throws Exception
	 */
	private function sign($expire, $msg, $suffix = '')
	{
		$expire = (int) $expire;
		$nonce = base_convert(mt_rand(), 10, 36);

		$msg[] = array('expire', $expire);
		$msg[] = array('nonce', $nonce);
		sort($msg);

		$msg_json = $this->encode($msg);
		$digest = hash_hmac('sha512', $msg_json, $this->key_secret_bin, TRUE);
		$digest_b64 = $this->unpadded_base64url_encode($digest);

		return sprintf('%s.%d.%s.%s.%s', $this->key_id, $expire, $nonce, $digest_b64, $suffix);
	}

	/**
	 * Encrypt metadata for user with a request_audience API call.
	 *
	 * @param float|integer  $expire
	 * @param array          $metadata (with string keys)
	 * @return string
	 * @throws Exception
	 */
	public function secure_metadata($expire, $metadata)
	{
		return $this->secure_metadata_for_user($expire, $metadata, NULL);
	}

	/**
	 * Encrypt metadata for use with a request_audience API call, by the
	 * specified user only.
	 *
	 * @param float|integer  $expire
	 * @param array          $metadata (with string keys)
	 * @param string|null    $user_id
	 * @return string
	 * @throws Exception
	 */
	public function secure_metadata_for_user($expire, $metadata, $user_id)
	{
		$msg = array(
			'expire' => $expire,
			'metadata' => $metadata,
		);

		if ($user_id !== NULL)
			$msg['user_id'] = $user_id;

		return $this->secure($msg);
	}

	/**
	 * @param mixed  $msg
	 * @return string
	 * @throws Exception
	 */
	private function secure($msg)
	{
		$msg_json = $this->encode($msg);

		$digest = hash('sha512', $msg_json, true);
		$msg_hashed = $digest . $msg_json;

		$block_size = 16;
		$block_mask = $block_size - 1;

		$hashed_size = strlen($msg_hashed);
		$padded_size = ($hashed_size + $block_mask) & ~$block_mask;

		$msg_padded = str_pad($msg_hashed, $padded_size, "\0");

		$iv = openssl_random_pseudo_bytes($block_size);

		$msg_encrypted = openssl_encrypt($msg_padded, 'AES-256-CBC', $this->key_secret_bin, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
		if (!$msg_encrypted)
			throw new Exception('Encryption error');

		$msg_iv = $iv . $msg_encrypted;
		$msg_b64 = $this->unpadded_base64url_encode($msg_iv);

		return sprintf('%s.%s', $this->key_id, $msg_b64);
	}

	/**
	 * @param mixed  $msg
	 * @return string
	 * @throws Exception
	 */
	private function encode($msg)
	{
		$result = json_encode($msg);
		if ($result === FALSE)
			throw new Exception('JSON encoding failed');

		return $result;
	}

	/**
	 * @param string  $data
	 * @return string
	 */
	private function unpadded_base64url_encode($data)
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
