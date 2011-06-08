<?php
/**
 * Unit-test clJsonNode implementation of clNode.
 */
class JsonNodeApiTests extends UnitTestCase {
  
  /**
   * Make sure my understanding of json_decode is spot-on
   */
  function testJsonDecode() {
    
    $json = '{"key":"value"}';
    $this->assertEqual((object) array('key' => 'value'), json_decode($json));
    
    $json = '[{"key":"value"}]';
    $this->assertEqual(array((object) array('key' => 'value')), json_decode($json));
    
  }
  
}