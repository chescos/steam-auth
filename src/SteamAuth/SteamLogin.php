<?php

namespace SteamAuth;

use SteamAPI\SteamAPI;
use phpseclib\Math\BigInteger;
use phpseclib\Crypt\RSA;

class SteamLogin
{
    public static function login($username, $password, $twoFactorCode = false)
    {
        $api = new SteamAPI();

        $data = $api->getRSAKey($username);

        $publicKeyExp = $data['publickey_exp'];
        $publicKeyMod = $data['publickey_mod'];

        $rsa = new RSA();
        $rsa->setEncryptionMode(RSA::ENCRYPTION_PKCS1);

        $n = new BigInteger($publicKeyMod, 16);
        $e = new BigInteger($publicKeyExp, 16);

        $key = [
            'modulus'           => $n,
            'publicExponent'    => $e
        ];

        $rsa->loadKey($key, RSA::PUBLIC_FORMAT_RAW);

        $encryptedPassword = base64_encode($rsa->encrypt($password, false));

        $params = [
            'username'      => $username,
            'password'      => $encryptedPassword,
            'rsatimestamp'  => $data['timestamp'],
            'captcha_gid'   => -1,
            'captcha_text'  => '',
            'emailauth'     => '',
            'emailsteamid'  => ''
        ];

        if($twoFactorCode) {
            $params['twofactorcode'] = $twoFactorCode;
        }

        // perform login
        return $api->doLogin($params);
    }
}
