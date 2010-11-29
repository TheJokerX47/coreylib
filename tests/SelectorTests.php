<?php 
/**
 * Unit-test our query parser.
 */
class SelectTests extends UnitTestCase {
  
  function testDescendantAndAddFlags() {
    $xml = '
      <xml>
        <foo>
          <bar>
            <dingle />
            <dingle />
            <dingle />
          </bar>
        </foo>
        <going>
          <here>
            <and>
              <there />
            </and>
          </here>
        </going>
      </xml>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
    $this->assertEqual(9, $xml->get('*')->size());
    
    $this->assertEqual(1, $xml->get('foo bar')->size());
    
    $this->assertEqual(3, $xml->get('foo bar')->get('*')->size());
    
    $xml = '
      <html>
        <body>
          <div id="foo">
            <b><a href="javascript:;">coming at yah!</a></b>
            <a href="http://fatpandadev.com">go here</a>
          </div>
          <p>
            <b><a href="javascript:;">more where that came from!</a></b>
          </p>
        </body>
      </html>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
    $this->assertEqual(2, $xml->get('b a')->size());
    $this->assertEqual(2, $xml->get('div a')->size());
    $this->assertEqual(3, $xml->get('body a')->size());
    $this->assertEqual(1, $xml->get('body > div > b > a')->size());
    $this->assertEqual(0, $xml->get('body > a')->size());
    $this->assertEqual(2, $xml->get('body > div a')->size());
    $this->assertEqual('go here', $xml->get('body > div a[href^="http"]'));
    
    $body = $xml->get('body');
    $this->assertEqual(1, $body->size());
    $this->assertEqual(2, $body->children()->size());
    $this->assertEqual(1, $body->children('div')->size());

    $group = $xml->get('body')->add('div')->add('a');
    $this->assertEqual(5, $group->size());
    $this->assertEqual('body', $group[0]->getName());
    $this->assertEqual('div', $group[1]->getName());
    $this->assertEqual('a', $group[2]->getName());
    $this->assertEqual('a', $group[3]->getName());
    $this->assertEqual('a', $group[4]->getName());
    
    $group = $xml->get('body, div, a');
    $this->assertEqual(5, $group->size());
    $this->assertEqual('body', $group[0]->getName());
    $this->assertEqual('div', $group[1]->getName());
    $this->assertEqual('a', $group[2]->getName());
    $this->assertEqual('a', $group[3]->getName());
    $this->assertEqual('a', $group[4]->getName());
  }
  
  function testSuffixes() {
    $sel = new clSelector('element:eq(10):first');
    $this->assertEqual(2, count($sel[0]->suffixes));
    $this->assertTrue(isset($sel[0]->suffixes['first']));
    $this->assertEqual("10", $sel[0]->suffixes['eq']);
  
    $sel = new clSelector('namespaced\:element:eq(10)');
    $this->assertEqual('namespaced:element', $sel->element);
    $this->assertEqual(1, count($sel->suffixes));
    $this->assertTrue(isset($sel->suffixes['eq']));
    $this->assertEqual("10", $sel->suffixes['eq']);
    
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
    
    $first_a = $xml->get(':first');
    $first_b = $xml->get('field:first');
    $this->assertEqual($first_a, $first_b);
    
    $this->assertEqual('red1', $xml->get(':first'));
    $this->assertEqual('barnone', $xml->get(':last'));
    $this->assertEqual('foo bar ipsum', $xml->get('[words^="foo"]:first'));
    $this->assertEqual('foobar ipsum', $xml->get('[words^="foo"]:last'));
    $this->assertEqual('checked', $xml->get(':eq(3)')->get('@checked'));
    
    $xml = '
      <xml>
        <empty1 />
        <empty2 />
        <nonempty1>value1</nonempty1>
        <nonempty2>value2</nonempty2>
      </xml>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
    $empty = $xml->get(':empty');
    $this->assertEqual(2, $empty->size());
    $this->assertEqual('empty1', $empty[0]->getName());
    $this->assertEqual('empty2', $empty[1]->getName());
    
    $parents = $xml->get(':parent');
    $this->assertEqual(2, $parents->size());
    $this->assertEqual('value1', $parents[0]);
    $this->assertEqual('value2', $parents[1]);
    
    $xml = '
      <xml>
        <pets>
          <cat age="3">Sampson</cat>
          <dog age="5">Buddy</dog>
        </pets>
        <pets>
          <cat age="8">Fluffy</cat>
          <dog age="13">Lacey</dog>
        </pets>
      </xml>
    ';
    
    $xml = clNode::getNodeFor($xml, 'xml');
    
    $pets = $xml->get(':has(dog)');
    $this->assertEqual(2, $pets->size());
    $this->assertEqual('Buddy', $pets[0]->get('dog'));
    $this->assertEqual('Lacey', $pets[1]->get('dog'));
  
    $lacey = $xml->get(':contains(Lacey)');
    $this->assertEqual(13, $lacey['age']);
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
    
    $sel = new clSelector('element[name="value"][foo!="bar"][final~="answer"]');
    $this->assertEqual('element', $sel->element);
    $this->assertEqual(array('name', 'foo', 'final'), $sel->attrib);
    $this->assertEqual(array('=', '!=', '~='), $sel->test);
    $this->assertEqual(array('value', 'bar', 'answer'), $sel->value);
  }
  
}