<?php
// rfc4648 style base32 encode/decode functions without padding

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

// Mirror the base64_encode() and base64_decode() functions

function base32_encode($data) {
    $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $bytes = unpack('C*', $data);
    $bin = '';
    foreach ($bytes as $byte) {
        $bin .= sprintf('%08b', $byte);
    }

    $r = '';
    while (strlen($bin)) {
        $c = substr($bin,0,5);
        $c = $c . str_repeat('0', 5 - strlen($c));
        $bin = substr($bin,5);
        $c = '000' . $c;
        $r .= $charset[bindec($c)];
    }
    
    return $r;
}

// This version is always strict, returns a false if it finds an invalid char
function base32_decode($data) {
    $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    $bin = '';
    foreach (str_split($data) as $c) {
        $pos = strpos($charset, $c);
        if ($pos === false) {
            return false;
        }
        $bin .= sprintf('%05b', $pos);
    }

    $pad = strlen($bin) & 7;
    if ($pad) {
        $bin = substr($bin, 0, strlen($bin) - $pad);
    }

    $raw = '';
    while (strlen($bin)) {
        $b = substr($bin,0,8);
        $raw .= pack('C', bindec($b));
        $bin = substr($bin,8);
    }
    return $raw;
}
