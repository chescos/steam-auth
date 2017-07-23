<?php

namespace SteamAuth;

class MobileAuth
{
	public function generateSteamGuardCode($sharedSecret)
	{
		$decodedSharedSecret = base64_decode($sharedSecret);
		// if you need steam time instead the local time, use 'false' (using local time the response time is less)
		$timeHash = $this->createTimeHash($this->getSteamTime(true));
		$hmac = $this->createHmac($timeHash, $decodedSharedSecret);
		$hmac = $this->startArrayToZero($hmac);

		$b = $this->intToByte(($hmac[19] & 0xF));
		$codePoint = ($hmac[$b] & 0x7F) << 24 | ($hmac[$b+1] & 0xFF) << 16 | ($hmac[$b+2] & 0xFF) << 8 | ($hmac[$b+3] & 0xFF);

		$steamChars = '23456789BCDFGHJKMNPQRTVWXY';
		$code = '';

		for($i = 0; $i < 5; $i++) {
			$code = $code . $steamChars{floor($codePoint) % strlen($steamChars)};
			$codePoint /= strlen($steamChars);
		}

		return $code;
	}

	protected function intToByte($int)
	{
		return $int & (0xff);
	}

	protected function startArrayToZero($array)
	{
		$mode = array();
		$intModeArray = 0;

		foreach($array as $test) {
			$mode[$intModeArray] = $this->intToByte($test);
			$intModeArray++;
		}

		return $mode;
	}

	protected function getSteamTime($localTime = false)
	{
		if($localTime) {
            return time() + 10;
        }

		$data = array('steamid' => 0);
		$url = 'http://api.steampowered.com/ITwoFactorService/QueryTime/v0001';
		$ch = curl_init($url);
		$postString = http_build_query($data, '', '&');
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postString);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$response = curl_exec($ch);
		$response = json_decode($response);
		curl_close($ch);

		return $response->response->serverTime;
	}

	protected function createTimeHash($time)
	{
		$time /= 30;
		$timeArray = array();

		for($i = 8; $i > 0; $i--) {
			$timeArray[$i - 1] = $this->intToByte($time);
			$time >>= 8;
		}

		$timeArray = array_reverse($timeArray);
		$newTimeArray = '';

		foreach($timeArray as $timeArrayValue) {
			$newTimeArray .= chr($timeArrayValue);
		}

		return $newTimeArray;
	}

	protected function createHmac($timeHash, $sharedSecretDecoded)
	{
		$hash = hash_hmac('sha1', $timeHash, $sharedSecretDecoded, false);
		$hmac = unpack('C*', pack('H*', $hash));

		return $hmac;
	}
}
