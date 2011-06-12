<?php 
/**
 * Unit-test our core.
 */
class FileCacheTests extends UnitTestCase {
  
  function testFileCache() {
    $this->assertNotEqual('', coreylib('http://feeds.feedburner.com/github', '10 seconds')->get('title'));
    $this->assertTrue(file_exists(clFileCache::getLastPath()));
    // the only way to really test this is to run it more than once
    // the second time you run it (within 10 seconds of the first), it should finish faster (no download)
    // after the 10 second window, running it should raise a U_NOTICE_ERROR announcing that the
    // cache has expired
  }
  
}