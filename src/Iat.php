<?php
/*
 * 接口认证令牌 Interface authentication token
 *
*/

namespace interfaceAuthToken\Iat;

use App\Master\Framework\Extend\Core;
use Illuminate\Http\Request;

class Iat
{

    private static $instance = null;

    private static $_Guard = 'app';

    private static $_Key = '5B9ADC14C705F1B041DDC2D9B16A2D94';

    private static $_Iv = '33092152342590AD';

    private static $_Users = [];

    private static $_Message;

    private static $_config;

    private function __construct($guard)
    {
        self::$_Guard = $guard;

        self::$_config = config('framework.auth');

        self::user();
    }

    public static function getInstance($guard = 'app')
    {
        if (!isset(self::$instance))
        {
            self::$instance = new self($guard);
        }
        return self::$instance;
    }


    public static function json($code = 200, $msg = 'success', $result = [])
    {
        if (!self::$_Users || !isset(self::$_Users['Iat']))
        {
            return response()->json(['code' => $code, 'msg' => $msg, 'result' => $result], 200, []);
        }

        if (!self::$_Users['Iat']['refresh'])
        {
            return response()->json(['code' => $code, 'msg' => $msg, 'result' => $result], 200, [
                'authorization' => self::$_Users['Iat']['authorization'],
                'hash' => self::$_Users['Iat']['hash']
            ]);
        }

        $iat = self::refresh(self::$_Users['Iat']['iat_auth']);

        return response()->json(['code' => $code, 'msg' => $msg, 'result' => $result], 200, $iat);
    }

    public static function login($data)
    {
        $response = ['hash' => '', 'authorization' => ''];

        $authorization_iv = self::random(8);

        $params = time() . '|' . $authorization_iv . '|' . isset(self::$_config['refresh'])?self::$_config['refresh']:0;

        $response['hash'] = self::encrypt($params, self::$_Key, self::$_Iv);

        $response['authorization'] = self::encrypt($data, self::$_Key, $authorization_iv);

        return $response;
    }

    public static function refresh($data = [])
    {
        if (!is_array($data) || empty($data)) {
            if (!self::$_Users['Iat']['iat_auth']) {
                self::setError(9050, 'IAT refresh failed, missing refresh data');
                return false;
            } else {
                $data = self::$_Users['Iat']['iat_auth'];
            }
        }

        return self::login($data);
    }

    public static function user()
    {
        if (!$authorization = Request::capture()->header('authorization'))
        {
            self::setError(91001, 'The authorization parameter is missing');
            return false;
        }

        if (!$hash = Request::capture()->header('hash'))
        {
            self::setError(91002, 'Missing hash parameter');
            return false;
        }

        if (self::$_Users && isset(self::$_Users['Iat']) && isset(self::$_Users['Iat']['iat_auth']))
        {
            if (!isset(self::$_Users['Iat']['iat_auth']['id']))
            {
                self::setError(91003, 'Failed to obtain user information');
                return false;
            }
            if (!$users = self::$_config['model']::where(['id' => self::$_Users['Iat']['iat_auth']['id']])->first())
            {
                self::setError(91004, 'Failed to obtain user information');
                return false;
            }

            return $users;
        }

        if (!$iat_hash = self::decrypt($hash, self::$_Key, self::$_Iv))
        {
            self::setError(91005, 'Hash decryption failed');
            return false;
        }

        $hash_params = explode('|', $iat_hash);


        if (isset($hash_params[2]) && $hash_params[2])
        {
            if (time() > (self::$_config['expire'] * 86400) + $hash_params[0])
            {
                self::setError(91006, 'Authorization decryption failed');
                return false;
            }
            if (time() > ($hash_params[0] + $hash_params[2]))
            {
                self::$_Users['Iat']['refresh'] = true;
            }
        }

        if (!isset($hash_params[1]) || !$hash_params[1])
        {
            $hash_params[1] = self::$_Iv;
        }

        if (!$iat_authorization = self::decrypt($authorization, self::$_Key, $hash_params[1]))
        {
            self::setError(9004, 'Authorization decryption failed');
            return false;
        }

        if (!isset($iat_authorization['id']))
        {
            self::setError(9005, 'User unique id not set');
            return false;
        }

        if (!$users = self::$_config['model']::where(['id' => $iat_authorization['id']])->first())
        {
            self::setError(9006, 'Failed to obtain user information');
            return false;
        }
        self::$_Users = $users->toArray();
        self::$_Users['Iat'] = [
            'refresh'       => false,
            'authorization' => $authorization,
            'hash'          => $hash,
            'iat_auth'      => $iat_authorization,
        ];

        return $users;
    }

    public static function check()
    {
        if (self::$_Users['Iat'] && isset(self::$_Users['Iat']['iat_auth']))
        {
            if (!isset(self::$_Users['Iat']['iat_auth']['id']))
            {
                return false;
            }

            return self::$_config['model']::where(['id' => self::$_Users['Iat']['iat_auth']['id']])->exists();
        } else {
            return self::user() ? true : false;
        }
    }

    public static function loginUser()
    {
        if (!$authorization = Request::capture()->header('authorization'))
        {
            Core::jsonResponse(91110, '用户信息认证失败，请重新登录！');
            return false;
        }

        if (!$hash = Request::capture()->header('hash'))
        {
            Core::jsonResponse(91110, '用户信息认证失败，请重新登录！');
            return false;
        }

        if (self::$_Users && isset(self::$_Users['Iat']) && isset(self::$_Users['Iat']['iat_auth']))
        {
            if (!$users = self::$_config['model']::where(['id' => self::$_Users['Iat']['iat_auth']['id']])->first())
            {
                Core::jsonResponse(91110, '用户信息认证失败，请重新登录！');
                return false;
            }
            return $users;
        }

        if (!$users = self::user())
        {
            Core::jsonResponse(91110, '用户信息认证失败，请重新登录！');
        }

        return $users;
    }

    public static function destroy()
    {

    }

    private static function random($length = 6, $chars = '')
    {
        $chars = '012FSDF34567DFD89qCVCXw3434ADeADrtyDSDFuioTRT4563RDSDSpasDXVXFdDF341SfghjJHGFD656SklzxFGFcvWEEWbnm';

        $hash = '';

        $max = strlen($chars) - 1;

        for ($i = 0; $i < $length; $i++) {
            $hash .= $chars[mt_rand(0, $max)];
        }

        return $hash;
    }

    /**
     * 加密字符串
     * @param string | array $data 字符串
     * @param string $key 加密key
     * @param string $iv 加密向量  E8F2920CDT6GQ396
     * @return string
     */
    private static function encrypt($data, $key = '', $iv = '')
    {
        $key = $key ? $key : self::$_Key;

        $iv = $iv ? $iv : self::$_Iv;

        $encrypted = openssl_encrypt(json_encode($data), "AES-256-CBC", $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode($encrypted);
    }

    /**
     * 解密字符串
     * @param string $data 字符串
     * @param string $key 加密key
     * @param string $iv 加密向量
     * @return object
     */
    private static function decrypt($data, $key, $iv)
    {
        $key = $key ? $key : self::$_Key;

        $iv = $iv ? $iv : self::$_Iv;

        $decrypted = openssl_decrypt(base64_decode($data), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        $json_str = rtrim($decrypted, "\0");

        return json_decode($json_str, true);
    }

    private static function setError($code, $msg, $res = '')
    {
        self::$_Message = ['code' => $code, 'msg' => $msg, 'res' => $res];
        return true;
    }

    public function error()
    {
        return self::$_Message;
    }

}


