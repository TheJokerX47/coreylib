<?php 
require('../coreylib.php');

// create a new instance of the coreylib clAPI class
$api = new clAPI('http://twitter.com/statuses/user_timeline.xml?screen_name=collegeman');
 	
// parse the feed, cache for as long as ten minutes
// for more options on specifying cache duration, see http://php.net/manual/en/function.strtotime.php
$api->parse('10 minutes');
	
//clAPI::configure('debug', TRUE);

// analyze your feed with the info() method:
$api->info();

// the most recent Tweet
echo $api->get('status[0]')->get('text');
/* or: */ echo $api->get('status[0]/text');

// the full name of the Twitter user
echo $api->get('status[0]')->get('user')->get('name');
/* or: */ echo $api->get('status[0]/user/name');

// and for the savvy, xpath support
$not_protected = $api->xpath('//status/user[protected[text()="false"]]'); 