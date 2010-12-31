<?php
// Firefox Sync Client (formerly called Weave)
//
// Sync is now built by default into Firefox 4 beta releases and the Fennec
// mobile client. This is a command line tool for reading the data out of a
// sync repository. For more detailed information about the protocol itself:
// 
// https://wiki.mozilla.org/Labs/Weave/User/1.0/API
// https://wiki.mozilla.org/Labs/Weave/Sync/1.0/API
//
// However, a major part of interacting with the service is being able to
// decrypt the records carried by the protocol. The encryption handling just
// underwent a pretty major overhaul to move away from using asymmetric
// algorithms completely. The sync services now use a simplified set of crypto
// described here:
//
// https://wiki.mozilla.org/Services/Sync/SimplifiedCrypto
//
// There's still a lot of documentation floating around that refers to the
// older schemes, and it can be difficult to figure out which parts are now
// relevant and which are outdated.

# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Firefox Sync Client
#
# The Initial Developer of the Original Code is Mike Rowehl
#
# Portions created by the Initial Developer are Copyright (C) 2010
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Mike Rowehl (mikerowehl@gmail.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

require_once('base32.php');

class Firefox_Sync {
    private $username = null;
    private $password = null;
    private $sync_key = null;
    private $base_url = null;
    private $bulk_keys = null;
    private $protocol_version = '1.0';

    public function __construct($username, $password, $sync_key, $base_url) {
        $this->set_credentials($username, $password);
        $this->set_sync_key($sync_key);
        $this->set_base_url($base_url);
    }

    public function set_credentials($username, $password) {
        $this->username = self::username_munge($username);
        $this->password = $password;
    }

    public function set_sync_key($sync_key) {
        $this->sync_key = $sync_key;
    }

    public function set_base_url($base_url) {
        $this->base_url = $base_url;
        if (substr($this->base_url, -1) != '/') {
            $this->base_url .= '/';
        }
        $this->base_url .=
            ($this->protocol_version . '/' . $this->username . '/');
    }

    public function collection_full($collection) {
        if ($this->bulk_keys === null) {
            $this->fetch_bulk_keys();
        }

        $r = array();
        $items = $this->fetch_json($this->base_url . 'storage/' . $collection .
            '?full=1');
        foreach ($items as $item) {
            $r[] = json_decode($this->c_decrypt(json_decode($item->payload), $collection));
        }
        return $r;
    }

    // If the username includes anything except URL characters, use the base32
    // encoded version of the sha1 of the name. That's too simple though.. so 
    // also lowercase the base32 once we get it back.
    // Static and public so that we can call this from other utilities that
    // require just a mucked up version of the username for things like 
    // constructing a URL.
    public static function username_munge($username) {
        if (preg_match('/[^A-Z0-9._-]/i', $username)) {
            $username = strtolower(base32_encode(sha1(strtolower($username), true)));
        }
        return $username;
    }

    // This is described somewhat in the simple encryption document at Mozilla.
    // The sync key as presented to the user is kinda sorta a base32 encoded
    // binary value. It's been converted to lowercase, and an l characters were
    // replaced with 8, and any o characters replaced with 9. So we need to get
    // it into shape where we can recover the binary value. And then we need to
    // run it through an hmac digest used to generate the symmetric encryption
    // key we can use to decrypt stuff.
    private function sync_key_to_enc_key() {
        $t = strtr($this->sync_key, array('8' => 'l', '9' => 'o', '-' => ''));
        $t = strtoupper($t);
        $raw_bits = base32_decode($t);
        $key = hash_hmac("sha256",
            'Sync-AES_256_CBC-HMAC256' . $this->username . chr(0x01),
            $raw_bits, true);
        return $key;
    }

    // Use the symmetric key generated from the sync_key to fetch the
    // crypto/keys collection, which has the default bulk key and any
    // collection specific keys.
    private function fetch_bulk_keys() {
        $json = $this->fetch_json($this->base_url . 'storage/crypto/keys');
        $keys = $this->c_decrypt(json_decode($json->payload), 'crypto');
        $default_keys = json_decode($keys);
        $this->bulk_keys = array('default' => 
            base64_decode($default_keys->default[0]));
    }

    // Decrypt using a symmetric key. There's some junk tacked onto the end of
    // the decrypted text, so trim the returned string down to just printable
    // characters. Not sure why that happens, but I found the same thing in
    // some code from Mozilla, so I'm pretty sure it's not just me flubbing the
    // crypto setup in some way. The payload should be an object with base64
    // encoded ciphertext and IV members, which is what comes back in the
    // records from the sync server.
    private function decrypt_payload($payload, $key) {
        $c = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($c, $key, base64_decode($payload->IV));
        $data = mdecrypt_generic($c, base64_decode($payload->ciphertext));

        $t = strrchr($data, '}');
        if ($t) {
            $data = substr($data, 0, 0 - (strlen($t)-1));
        }
        return $data;
    }

    // Collection decrypt. Lookup the collection in the bulk keys list and
    // find the relevant key to use. There's a special case for the crypto
    // collection, which uses a key based off a transform of the sync key.
    private function c_decrypt($payload, $collection) {
        if ($collection == 'crypto') {
            $key = $this->sync_key_to_enc_key($this->sync_key,
                $this->username);
        } else {
            if (array_key_exists($collection, $this->bulk_keys)) {
                $key = $this->bulk_keys[$collection];
            } else {
                $key = $this->bulk_keys['default'];
            }
        }
        return $this->decrypt_payload($payload, $key);
    }

    // Lots of json unwrappering to do all over the place, so define an http
    // fetch function that applies at least one of the levels of unwrapping
    // for us
    private function fetch_json($url) {
        return json_decode($this->fetch($url));
    }

    private function fetch($url) {
        $h = curl_init($url);
        curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($h, CURLOPT_USERPWD,
            $this->username . ':' . $this->password);
        curl_setopt($h, CURLOPT_SSL_VERIFYPEER, false);

        $r = curl_exec($h);
        $headers = curl_getinfo($h);
        curl_close($h);

        if ($headers['http_code'] != 200) {
            throw new Exception('' . $headers['http_code'] . " resp $url");
        }

        return $r;
    }
}

