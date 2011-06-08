<?php 
/**
 * Unit-test our core.
 */
class CoreTests extends UnitTestCase {
  
  function testDownloadAndParse() {
    echo coreylib('http://feeds.feedburner.com/github')->get('title');
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github')->get('title'));
  }
  
}