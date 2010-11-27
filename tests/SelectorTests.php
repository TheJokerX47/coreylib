<?php 
/**
 * Unit-test our query parser.
 */
class SelectTests extends UnitTestCase {
  
  function testSuffixes() {
    $xml = '
      <xml>
        <field color="red">red1</field>
        <field color="blue">blue</field>
        <field color="red">red2</field>
        <field checked="checked">true</field>
        <field words="foo bar ipsum">foo bar ipsum</field>
        <field words="foobar ipsum">foobar ipsum</field>
        <field words="barnone" other="false">barnone</field>
      </xml>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
  }
  
  function testAttributeTests() {
    $xml = '
      <xml>
        <field color="red">red1</field>
        <field color="blue">blue</field>
        <field color="red">red2</field>
        <field checked="checked">true</field>
        <field words="foo bar ipsum">foo bar ipsum</field>
        <field words="foobar ipsum">foobar ipsum</field>
        <field words="barnone" other="false">barnone</field>
      </xml>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
    // exists
    $this->assertEqual("true", $xml->first('field[checked]'));
    
    // equal
    $this->assertEqual(array(), $xml->get('field[checked="no"]')->toArray());
    
    // equal, multiple results
    $fields = $xml->get('field[color="red"]');
    $this->assertEqual(2, $fields->size());
    $this->assertEqual("red1", $fields[0]);
    $this->assertEqual("red2", $fields[1]);
    
    // not equal
    $fields = $xml->get('field[color!="red"]');
    $this->assertTrue($fields->size() >= 1);
    $this->assertEqual('blue', $fields[0]['color']);
    
    // space-delimited word
    $fields = $xml->get('field[words~="foo"]');
    $this->assertEqual(1, $fields->size());
    $this->assertEqual("foo bar ipsum", $fields[0]);
    
    // starts with
    $fields = $xml->get('field[words^="foo"]');
    $this->assertEqual(2, $fields->size());
    
    // ends with
    $fields = $xml->get('field[words$="ipsum"]');
    $this->assertEqual(2, $fields->size());
    
    // contains
    $fields = $xml->get('field[words*="bar"]');
    $this->assertEqual(3, $fields->size());
    
    // old style value aggregation
    $colors = $xml->get('field@color');
    $this->assertEqual(array('red', 'blue', 'red'), $colors->toArray());
    
    // multiple attributes
    $fields = $xml->get('field[words*="bar"][other!="true"]');
    $this->assertEqual('barnone', $fields[0]);
  }
  
  function testParser() {
    
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
    $this->assertEqual('attrib', $sel[0]->attrib[0]);
    
    $sel = new clSelector("element1[attrib]");
    $this->assertEqual(1, $sel->size());
    $this->assertEqual('element1', $sel[0]->element);
    $this->assertEqual('attrib', $sel[0]->attrib[0]);
    
    $sel = new clSelector('element1 element2[attrib="value"]');
    $this->assertEqual(2, $sel->size());
    $this->assertEqual('element2', $sel[1]->element);
    $this->assertEqual('attrib', $sel[1]->attrib[0]);
    $this->assertEqual('value', $sel[1]->value[0]);
    $this->assertEqual('=', $sel[1]->test[0]);
    
    $sel = new clSelector('element2[attrib|="value"]');
    $this->assertEqual('|=', $sel[0]->test[0]);
    
    $sel = new clSelector('element2[attrib*="value"]');
    $this->assertEqual('*=', $sel[0]->test[0]);
    
    $sel = new clSelector('element2[attrib~="value"]');
    $this->assertEqual('~=', $sel[0]->test[0]);
    
    $sel = new clSelector('element2[attrib!="value"]');
    $this->assertEqual('!=', $sel[0]->test[0]);
    
    $sel = new clSelector('element2[attrib^="value"]');
    $this->assertEqual('^=', $sel[0]->test[0]);
    
    $sel = new clSelector('element2[attrib$="value"]');
    $this->assertEqual('$=', $sel[0]->test[0]);
    
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
    
    $sel = new clSelector('element[name="value"][foo!="bar"][final~="answer"]');
    $this->assertEqual('element', $sel->element);
    $this->assertEqual(array('name', 'foo', 'final'), $sel->attrib);
    $this->assertEqual(array('=', '!=', '~='), $sel->test);
    $this->assertEqual(array('value', 'bar', 'answer'), $sel->value);
  }
  
}