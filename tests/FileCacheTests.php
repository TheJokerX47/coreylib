<?php 
/**
 * Unit-test our core.
 */
class FileCacheTests extends UnitTestCase {
  
  function testFileCache() {
    $this->assertEqual('The GitHub Blog', coreylib('http://feeds.feedburner.com/github', '10 seconds')->get('title'));
    $this->assertTrue(file_exists(clFileCache::getLastPath()));
    
    // the only way to really test this is to run it more than once
    // the second time you run it (within 10 seconds of the first), it should finish faster (no download)
    // after the 10 second window, running it should raise a U_NOTICE_ERROR announcing that the
    // cache has expired
  }

  function testDirectCaching() {
    $cache_key = 'hello-world';

    if (!clCache::cached($cache_key, '10 minutes')) {
      echo 'Hello, world!';
      clCache::save();
    }

    $this->assertEqual('Hello, world!', clCache::read($cache_key));

    clCache::delete($cache_key);

    $this->assertFalse(clCache::read($cache_key));
  }
  
}