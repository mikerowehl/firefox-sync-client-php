<?php
// Ghetto arg parsing, we need at least 5 things:
//   username - username for http auth
//   password - password for http auth
//   sync_key - the key used to start unwrapping encryption
//   url_base - the url where the sync server lives
//   collection - the name of the collection to dump
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
#
require_once('sync.php');

$garbage = array_shift($argv); // script name, discard
$username = array_shift($argv);
$password = array_shift($argv);
$sync_key = array_shift($argv);
$url_base = array_shift($argv);
$collection = array_shift($argv);

$sync = new Firefox_Sync($username, $password, $sync_key, $url_base);
print_r($sync->collection_full($collection));
