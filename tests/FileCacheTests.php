<?php 
/**
 * Unit-test our core.
 */
class FileCacheTests extends UnitTestCase {
  
  function testFileCache() {
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github', '10_minutes')->get('title'));
  }
  
}