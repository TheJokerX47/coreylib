<?php 
class SelectTests extends UnitTestCase {
  
  function testSelector() {
    
    $sel = new clSelector("element1 element2     element3@attrib");
    $this->assertEqual(3, $sel->size());
    
    foreach($sel as $i => $s) {
      $this->assertFalse($s->is_expression);
      $this->assertEqual("element".($i+1), $s->element);
      if ($i == 2) {
        $this->assertEqual('attrib', $s->attrib);
      }
    }
    
    $sel = new clSelector("element1/element2/element3@attrib");
    $this->assertEqual(3, $sel->size());
    
    foreach($sel as $i => $s) {
      $this->assertFalse($s->is_expression);
      $this->assertEqual("element".($i+1), $s->element);
      if ($i == 2) {
        $this->assertEqual('attrib', $s->attrib);
      }
    }
    
    $sel = new clSelector("element1[@attrib]");
    $this->assertEqual(1, $sel->size());
    $this->assertEqual('element1', $sel[0]->element);
    $this->assertEqual('attrib', $sel[0]->attrib);
    
    $sel = new clSelector("element1[attrib]");
    $this->assertEqual(1, $sel->size());
    $this->assertEqual('element1', $sel[0]->element);
    $this->assertEqual('attrib', $sel[0]->attrib);
    
    $sel = new clSelector('element1 element2[attrib="value"]');
    $this->assertEqual(2, $sel->size());
    $this->assertEqual('element2', $sel[1]->element);
    $this->assertEqual('attrib', $sel[1]->attrib);
    $this->assertEqual('value', $sel[1]->value);
    $this->assertEqual('=', $sel[1]->test);
    
    $sel = new clSelector('element2[attrib|="value"]');
    $this->assertEqual('|=', $sel[0]->test);
    
    $sel = new clSelector('element2[attrib*="value"]');
    $this->assertEqual('*=', $sel[0]->test);
    
    $sel = new clSelector('element2[attrib~="value"]');
    $this->assertEqual('~=', $sel[0]->test);
    
    $sel = new clSelector('element2[attrib!="value"]');
    $this->assertEqual('!=', $sel[0]->test);
    
    $sel = new clSelector('element2[attrib^="value"]');
    $this->assertEqual('^=', $sel[0]->test);
    
    $sel = new clSelector('element2[attrib$="value"]');
    $this->assertEqual('$=', $sel[0]->test);
    
    $sel = new clSelector('element1[1] element2[2] element3[4]@attrib element4[8]');
    $this->assertEqual("1", $sel[0]->suffixes['eq']);
    $this->assertEqual("2", $sel[1]->suffixes['eq']);
    $this->assertEqual("4", $sel[2]->suffixes['eq']);
    $this->assertEqual("8", $sel[3]->suffixes['eq']);
    
    $sel = new clSelector('element:eq(10):first');
    $this->assertEqual(2, count($sel[0]->suffixes));
    $this->assertTrue(isset($sel[0]->suffixes['first']));
    $this->assertEqual("10", $sel[0]->suffixes['eq']);
  
    $sel = new clSelector('namespaced\:element:eq(10)');
    $this->assertEqual('namespaced:element', $sel->element);
    $this->assertEqual(1, count($sel->suffixes));
    $this->assertTrue(isset($sel->suffixes['eq']));
    $this->assertEqual("10", $sel->suffixes['eq']);
  }
  
}