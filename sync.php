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

require_once('username_munge.php');

// Outupt to stderr, cause this is a command line tool.
function error($message) {
    file_put_contents('php://stderr', $message . "\n");
}

function http_fetch($url, $u, $p) {
    $h = curl_init($url);
    curl_setopt($h, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($h, CURLOPT_USERPWD, $u . ':' . $p);
    curl_setopt($h, CURLOPT_SSL_VERIFYPEER, false);

    $r = curl_exec($h);
    $headers = curl_getinfo($h);
    curl_close($h);

    if ($headers['http_code'] != 200) {
        error($headers['http_code'] . " http response to $url:");
        error("  response body: $r");
        return null;
    }

    return $r;
}

// This is described somewhat in the simple encryption document at Mozilla.
// The sync key as presented to the user is kinda sorta a base32 encoded
// binary value. It's been converted to lowercase, and an l characters were
// replaced with 8, and any o characters replaced with 9. So we need to get
// it into shape where we can recover the binary value. And then we need to
// run it through an hmac digest used to generate the symmetric encryption
// key we can use to decrypt stuff.
function sync_key_to_enc_key($sync_key, $username) {
    $sync_key = strtr($sync_key, array('8' => 'l', '9' => 'o', '-' => ''));
    $sync_key = strtoupper($sync_key);
    $raw_bits = base32_decode($sync_key);
    $key = hash_hmac("sha256", 'Sync-AES_256_CBC-HMAC256' . $username . chr(0x01), $raw_bits, true);
    return $key;
}

// Decrypt using a symmetric key. There's some junk tacked onto the end of
// the decrypted text, so trim the returned string down to just printable
// characters. Not sure why that happens, but I found the same thing in some
// code from Mozilla, so I'm pretty sure it's not just me flubbing the crypto
// setup in some way. The payload should be an object with base64 encoded
// ciphertext and IV members, which is what comes back in the records from the
// sync server.
function decrypt_payload($payload, $key) {
    $c = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
    mcrypt_generic_init($c, $key, base64_decode($payload->IV));
    $data = mdecrypt_generic($c, base64_decode($payload->ciphertext));

    $t = strrchr($data, '}');
    if ($t) {
        $data = substr($data, 0, 0 - (strlen($t)-1));
    }
    return $data;
}

// Ghetto arg parsing, we need at least 4 things:
//   username - username for http auth
//   password - password for http auth
//   sync_key - the key used to start unwrapping encryption
//   url_base - the url where the sync server lives
//
// The username and password are used to fetch http resources from the server,
// these come in the form of JSON responses generally.  However, the fields
// within the JSON responses are encrypted using a series of keys.  The
// process starts off from a shared private key called the sync key.  On
// desktop Firefox you can get this from Preferences - Sync - Manage Account -
// My Sync Key. It should look something like this:
//   x-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx
// Where each x is an alphanumeric (this is a base32 encoded key actually)
//
// The url is the base path used by the weave server, the sync service. If
// you're using Mozilla's public sync servers you can figure out the server 
// to use by running 'node_lookup.php' to get the URL. If you're
// running your own sync server it's just the base of the install, same as
// you used for the services.sync.serverURL setting in Firefox.

$garbage = array_shift($argv); // script name, discard
$username = username_munge(array_shift($argv));
$password = array_shift($argv);
$sync_key = array_shift($argv);
$url_base = array_shift($argv);

$data = http_fetch($url_base . '1.0/' . $username . '/storage/crypto/keys', $username, $password);
$json = json_decode($data);
$payload = json_decode($json->payload);

$key = sync_key_to_enc_key($sync_key, $username);
$key_json = decrypt_payload($payload, $key);
$default_keys = json_decode($key_json);
$default_enc_key = base64_decode($default_keys->default[0]);

$history = http_fetch($url_base . '1.0/' . $username . '/storage/history?full=1', $username, $password);

$history_items = json_decode($history);
foreach ($history_items as $item) {
    $r = decrypt_payload(json_decode($item->payload), $default_enc_key);
    $h = json_decode($r);
    echo $h->histUri . "\n";
}
