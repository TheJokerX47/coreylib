<?php 
/**
 * Unit-test our core.
 */
class FileCacheTests extends UnitTestCase {
  
  function testFileCache() {
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github', '3 seconds')->get('title'));
  }
  
}