<?php 

abstract class JwtUtil{
    static function generateToken($user){
        if (empty($user)) {
            return null;
        }

        $data = array(
            'User' =>  [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'role' => $user['role'],

                // expires in 1 year
                'exp' => time() + 3600 * 24 * 365
                
            ]
        );

        $token = JWT::encode($data, Configure::read('Security.salt'));
        return $token;
    }

    static function decodeToken($token){
        $data = JWT::decode($token, Configure::read('Security.salt'), array('HS256'));
        return $data;
    }
}