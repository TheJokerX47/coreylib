<?php
class CurlMultiTests extends UnitTestCase {
  
  function testBasicCurlMulti() {
    $start = microtime(true);
    
    $feeds = array(
      'http://feeds.feedburner.com/52WeeksOfUx',
      'http://www.alistapart.com/site/rss',
      'http://cameronmoll.tumblr.com/rss',
      'http://chrome.blogspot.com/feeds/posts/default',
      'http://codeigniter.com/feeds/atom/full/'
      /*
      'http://culturedcode.com/things/blog/feed',
      'https://sivers.org/en.atom',
      'http://blog.disqus.com/rss',
      'http://blog.facebook.com/atom.php',
      'http://developers.facebook.com/blog/feed',
      'http://flowplayer.org/blog/rss.xml',
      'http://feeds.feedburner.com/github',
      'http://googlewebmastercentral.blogspot.com/feeds/posts/default',
      'http://graemerocher.blogspot.com/feeds/posts/default',
      'http://blog.jquery.com/feed/',
      'http://kennethreitz.com/feeds/all.atom.xml'
      */
    );
    
    $multi = clApi::exec($feeds);
    
    $multi_speed = microtime(true) - $start;
    
    $start = microtime(true);
    
    $ind = array();
    
    foreach($feeds as $i => $feed) {
      $api = new clApi($feed);
      $api->parse();
      $ind[] = $api;
    }
    
    $ind_speed = microtime(true) - $start;
    
    $this->assertTrue($multi_speed < $ind_speed, "Speed!");
    
    for($i = 0; $i<count($feeds); $i++) {
      $this->assertTrue((bool) $ind[$i]->getContent());
      $this->assertEqual($multi[$i]->api->getContent(), $ind[$i]->getContent());
    }
    
    echo "$multi_speed\n";
    echo "$ind_speed\n";
  }
  
}