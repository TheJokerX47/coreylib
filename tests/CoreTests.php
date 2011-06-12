<?php 
/**
 * Unit-test our core.
 */
class CoreTests extends UnitTestCase {
  
  function testDownloadAndParse() {
    $this->assertEqual('The GitHub Blog', coreylib('http://feeds.feedburner.com/github')->get('title'));
  }
  
}