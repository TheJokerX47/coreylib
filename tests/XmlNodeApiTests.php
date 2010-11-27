<?php
/**
 * Unit-test clXmlNode implementation of clNode.
 */
class XmlNodeApiTests extends UnitTestCase {

  function testBasic() {
    $xml = "
      <people>
        <person name='Aaron Collegeman'>
          <pets>
            <pet name='Buddy' type='dog' />
          </pets>
          <kids count='1'>
            <kid name='Jared Collegeman' />
          </kids>
        </person>
        <person name='Karla Collegeman'>
          <kids count='1'>
            <kid name='Isabela Collegeman' />
          </kids>
        </person>
      </people>
    ";
    
    $sxe = simplexml_load_string($xml);
    
    // make sure SimpleXMLElement is working properly
    $this->assertEqual('people', $sxe->getName());
    // wrap in clXmlNode
    $people = clNode::getNodeFor($xml, 'xml');
    // same test as on SXE above
    $this->assertEqual('people', $people->getName());
    // get the "person" children of people
    $persons = $people->get('person');
    // there should be two of them
    $this->assertEqual(2, $persons->size());
    $names = $people->get('person kids kid@name');
    $this->assertEqual(2, $names->size());
    $this->assertEqual('Jared Collegeman', @$names[0]);
    $this->assertEqual('Isabela Collegeman', @$names[1]);
  }
  
  function testMultiplicity() {
    $xml = "
      <employment>
        <employer>
          <employee />
          <employee />
          <employee />
          <employee />
          <employee />
        </employer>
        <employer>
          <employee />
          <employee />
          <employee />
          <employee />
          <employee />
        </employer>
      </employment>
    ";
    
    $employment = clNode::getNodeFor($xml, 'xml');
    $employees = $employment->get('employer employee');
    $this->assertEqual(10, $employees->size());
  }
  
  function testRecursiveAggregation() {
    $xml = "
      <pets>
        <dogs>
          <dog name='Buddy' />
        </dogs>
        <dogs>
          <dog name='Lacey' />
        </dogs>
        <cats>
          <cat name='Fluffy' />
        </cats>
      </pets>
    ";
    
    $sxe = simplexml_load_string($xml);
    
    // make sure SimpleXMLElement is working properly
    $this->assertEqual('pets', $sxe->getName());
    // wrap in clXmlNode
    $pets = clNode::getNodeFor($xml, 'xml');
    // same test as on SXE above
    $this->assertEqual('pets', $pets->getName());
    // aggregate dog names
    $this->assertEqual(array('Buddy', 'Lacey'), $pets->get('dogs dog@name')->toArray());
  }
  
  function testNamespaces() {
    $xml = "
      <their:pets xmlns:their='http://fatpandadev.com/coreylib/tests/their' xmlns:his='http://fatpandadev.com/coreylib/tests/his' xmlns:her='http://fatpandadev.com/coreylib/tests/her'>
        <his:dogs>
          <dog name='Buddy' />
        </his:dogs>
        <her:dogs>
          <dog name='Lacey' />
        </her:dogs>
      </their:pets>
    ";
    
    $sxe = simplexml_load_string($xml);
    
    // make sure SimpleXMLElement is working properly
    $this->assertEqual('pets', $sxe->getName());
    // wrap in clXmlNode
    $pets = clNode::getNodeFor($xml, 'xml');
    // same test as on SXE above
    $this->assertEqual('pets', $pets->getName());
    // aggregate dog names
    $this->assertEqual(array('Buddy', 'Lacey'), $pets->get('dogs dog@name')->toArray());
    
    $names = $pets->get('dogs dog@name');
    $this->assertEqual('Buddy', $names[0]);
    
    $dogs = $pets->get('dogs dog');
    $this->assertEqual('Buddy', $dogs['name']);
    $this->assertEqual('Buddy', $dogs->get('@name'));
    $this->assertEqual('Buddy', $pets->get('dogs dog')->get('@name'));
  }
  
}