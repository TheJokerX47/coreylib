<?php
class XmlNodeApiTests extends UnitTestCase {

  function testBasic() {
    $xml = "
      <people>
        <person name='Aaron Collegeman'>
          <pets>
            <pet name='Buddy' type='dog' />
          </pets>
          <kids count='1'>
            <kid name='Isabela Collegeman' />
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
    $this->assertEqual(2, count($persons));
    
    $names = $people->get('person/kids/kid@name');
    $this->assertEqual(2, count($names));
    $this->assertEqual('Isabela Collegeman', $names[0]);
    $this->assertEqual('Isabela Collegeman', $names[1]);
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
    $employees = $employment->get('employer/employee');
    $this->assertEqual(10, count($employees));
  }
  
  function testNamespaces() {
    $xml = simplexml_load_string("
      <their:pets xmlns:his='http://fatpandadev.com/coreylib/tests/his' xmlns:her='http://fatpandadev.com/coreylib/tests/her'>
        <his:dogs>
          <dog name='Buddy' />
        </his:dogs>
        <her:dogs>
          <dog name='Lacey' />
        </her:dogs>
      </their:pets>
    ");
    
    $sxe = simplexml_load_string($xml);
    
    // make sure SimpleXMLElement is working properly
    $this->assertEqual('pets', $sxe->getName());
    // wrap in clXmlNode
    $pets = clNode::getNodeFor($xml, 'xml');
    // same test as on SXE above
    $this->assertEqual('pets', $pets->getName());
    // his Dog's name is Buddy
    $this->assertEqual('Buddy', $pets->get('dogs[0]/dog[0]@name'));
    // her Dog's name is Lacey
    $this->assertEqual('Lacey', $pets->get('dogs[1]/dog[0]@name'));
  }
  
}