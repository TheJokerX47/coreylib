<?php
// load simpletest
// http://www.simpletest.org
require_once('simpletest/autorun.php');
require_once('../coreylib.php');

class TestCoreylib extends UnitTestCase {

	function testText() {
		$api = new clAPI("
			<root>
				<node>node value</node>
				<node att='att value'></node>
			</root>
		");
		
		$this->assertTrue($api->parse());
		$this->assertEqual("node value", $api->text('node[0]'));
		$this->assertEqual("att value", $api->text('node[1]@att'));
	}

	function testJsonParsing() {
		$api = new clAPI("http://api.twitter.com/1/statuses/public_timeline.json");
		echo $api->parse();
	}

}