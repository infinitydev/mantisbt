<?php

require_once(__DIR__ . '/yubicloud.class.php');

class YubikeyAuth {
    private $yubi;
    private $origUsername;
    private $mapFunc;

    public function __construct($client_id, $secret_key = '', $server_list = null, $https=false) {
        $this->yubi = new Yubicloud($client_id, $secret_key, $server_list, $https);
    }

    /**
     * Check if a username+password pair is a valid login.
     */
    public function authenticate ($username, $password) {
        $userLen = strlen($this->origUsername);
        $passLen = strlen($password);

        if ($passLen==44 && $userLen==0 && $this->yubi->isModHex($password)) {
            // Username is user-supplied => check that matches the associated Yubikey ID
            if ($this->getCanonicalName($password)!=$username)
                return false;
            $result = $this->yubi->checkOnYubiCloud(strtolower($password));
            if ($result=='OK')
                return true;
        } else if ($userLen==44 && passLen==0 && !$this->requireUsername($username)) {
            $result = $this->yubi->checkOnYubiCloud(strtolower($this->origUsername));
            if ($result=='OK')
                return true;
        }
        
        return false;
    }

    public function strict () {
        /**
         * Allow normal password authentication as fallback.
         */
        return false;
    }

    public function requireUsername($username) {
        return true;
    }

    public function getCanonicalName ($username) {
        if (strlen($username)==44 && $this->yubi->isModHex($username)) {
            $this->origUsername = strtolower($username);
            $yubikey_id = $this->getYubikeyId($username);
            if (is_callable($this->mapFunc)) {
                $translatedUsername = call_user_func($this->mapFunc, $yubikey_id);
                if ($translatedUsername) {
                    return $translatedUsername;
                }
            } else {
                return $yubikey_id;
            }
        }

        return $username;
    }

    public function setPublicIdMapFunc($mapFunc) {
        $this->mapFunc = $mapFunc;
    }

    private function getYubikeyId($username) {
        return strtolower(substr($username, 0, 12));
    }
}
