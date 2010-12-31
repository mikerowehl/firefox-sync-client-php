<?php
// Firefox Sync Client (formerly called Weave)
//
// The Sync service provided by Mozilla provides for mapping user accounts to
// node machines.  That means in order to figure out which public endpoint you
// should be hitting to retrieve your sync data you first need to lookup the
// weave node your account maps to. This is mostly described at:
//
// https://wiki.mozilla.org/Labs/Weave/User/1.0/API
//
// There are some parts left out however, like the fact that 'username' used
// in these urls is actually a lowercase converted base32 encoded version of
// the sha1 hash of the username if the username contains anything besides
// alphanumeric characters or a dash, underscore, or period. Ugh.
//
// This wrappers hitting the user endpoint to find out which sync endpoint to
// query for actual data.

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

require_once('sync.php');

$garbage = array_shift($argv); // this is the name of the script

// We definitely need a username
$username = Firefox_Sync::username_munge(array_shift($argv));

// This hostname will work by default for the mozilla service, so only need to
// include a second argument if you want to hit your own sync server
$base_url = 'https://auth.services.mozilla.com/user/';
if (count($argv)) {
    $base_url = array_shift($argv);
}

// No auth required, so just rely on the file wrappers instead of curl
$full_url = $base_url . '1.0/' . $username . '/node/weave';
echo "Querying $full_url\n";
echo "Node endpoint: " . file_get_contents($full_url) . "\n";
