<?php 
/**
 * Unit-test our core.
 */
class FileCacheTests extends UnitTestCase {
  
  function testFileCache() {
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github', '2 seconds')->get('title'));
    $this->assertTrue(file_exists(clFileCache::getLastPath()));
    usleep(2500000);
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github', -1)->get('title'));
    $this->assertFalse(file_exists(clFileCache::getLastPath()));
  }
  
}