<?php 
/**
 * Unit-test our core.
 */
error_reporting(-1);
class CoreTests extends UnitTestCase {
  
  function testDownloadAndParse() {
    $api = new clApi('http://www.squidoo.com/topics/books-poetry-writing?top');
    $download = $api->download();
    $this->assertTrue($download->is200());
    $this->assertFalse($download->is404());
    $this->assertFalse($download->is500());
    
    $xml = clNode::getNodeFor($download->getContent(), 'xml');
    echo $xml->toJson();
  }
  
}