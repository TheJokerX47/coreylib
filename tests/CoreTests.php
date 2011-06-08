<?php 
/**
 * Unit-test our core.
 */
class CoreTests extends UnitTestCase {
  
  function testDownloadAndParse() {
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github')->get('title'));
  }
  
}