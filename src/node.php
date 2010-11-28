<?php
/**
 * coreylib - Standard API for navigating data: XML and JSON
 * Copyright (C)2008-2010 Fat Panda LLC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. 
 */

/**
 * Parser for jQuery-inspired selector syntax.
 */
class clSelector implements ArrayAccess, Iterator {
  
  static $sep = "#(\s+|/)#";
  
  static $regex;
  
  static $attrib_exp;
  
  private $selectors = array();
  
  private $i = 0;
  
  static $tokenize = array('#', ';', '&', ',', '.', '+', '*', '~', "'", ':', '"', '!', '^', '$', '[', ']', '(', ')', '=', '>', '|', '/', '@', ' ');
  
  private $tokens;
  
  private function tokenize($string) {
    $tokenized = false;
    foreach(self::$tokenize as $t) {
      while(($at = strpos($string, "\\$t")) !== false) {
        $tokenized = true;
        $token = "TKS".count($this->tokens)."TKE";
        $this->tokens[] = $t;
        $string = substr($string, 0, $at).$token.substr($string, $at+2);
      }
    }
    return $tokenized ? 'TK'.$string : $string;
  }
  
  private function untokenize($string) {
    if (!$string || strpos($string, 'TK') !== 0) {
      return $string;
    } else {
      foreach($this->tokens as $i => $t) {
        $token = "TKS{$i}TKE";
        $string = preg_replace("/{$token}/", $t, $string);
      }
      return substr($string, 2);
    }
  }
  
  function __construct($query) {
    if (!self::$regex) {
      self::$regex = self::generateRegEx();
    }

    if ($query == '*') {
      $selectors = array('*');
    } else {
      $tokenized = $this->tokenize($query);
      if (!($selectors = preg_split(self::$sep, $tokenized))) {
        throw new clException("Failed to parse selector query [$query].");
      }
    } 
    
    foreach($selectors as $sel) {
      if (!preg_match(self::$regex, $sel, $matches)) {
        throw new clException("Failed to parse [$sel], part of query [$query].");
      }
      
      $sel = (object) array(
        'element' => $this->untokenize(@$matches['element']),
        'is_expression' => ($this->untokenize(@$matches['attrib_exp']) != false),
        // in coreylib v1, passing "@attributeName" retrieved a scalar value;
        'is_attrib_getter' => preg_match('/^@.*$/', $query),
        // defaults for these:
        'attrib' => null,
        'value' => null,
        'suffixes' => null,
        'test' => null
      );
      
      // default element selection is "all," as in all children of current node
      if (!$sel->element && !$sel->is_attrib_getter) {
        $sel->element = '*';
      }
      
      if ($exp = @$matches['attrib_exp']) {
        // multiple expressions?
        if (strpos($exp, '][') !== false) {
          $attribs = array();
          $values = array();
          $tests = array();
          
          $exps = explode('][', substr($exp, 1, strlen($exp)-2));
          foreach($exps as $exp) {
            if (preg_match('#'.self::$attrib_exp.'#', "[{$exp}]", $matches)) {
              $attribs[] = $matches['attrib_exp_name'];
              $tests[] = $matches['test'];
              $values[] = $matches['value'];
            }
          }
          
          $sel->attrib = $attribs;
          $sel->value = $values;
          $sel->test = $tests;
        // just one expression
        } else {
          $sel->attrib = array($this->untokenize(@$matches['attrib_exp_name']));
          $sel->value = array($this->untokenize(@$matches['value']));
          $sel->test = array(@$matches['test']);
        }
      // no expression
      } else {
        $sel->attrib = $this->untokenize(@$matches['attrib']);
      }
      
      if ($suffixes = @$matches['suffix']) {
        $all = array_filter(explode(':', $suffixes));
        $suffixes = array();
        
        foreach($all as $suffix) {
          $open = strpos($suffix, '(');
          $close = strrpos($suffix, ')');
          if ($open !== false && $close !== false) {
            $label = substr($suffix, 0, $open);
            $val = $this->untokenize(substr($suffix, $open+1, $close-$open-1));
          } else {
            $label = $suffix;
            $val = true;
          }
          $suffixes[$label] = $val;
        }
        
        $sel->suffixes = $suffixes;
      }
      
      // alias for eq(), and backwards compat with coreylib v1
      if (!isset($sel->suffixes['eq']) && ($index = @$matches['index'])) {
        $sel->suffixes['eq'] = $index;
      }
      
      $this->selectors[] = $sel;
    }
  }
  
  function __get($name) {
    $sel = $this->selectors[$this->i];
    return $sel->{$name};
  }
  
  function has_suffix($name) {
    $sel = $this->selectors[$this->i];
    return @$sel->suffixes[$name];
  }
  
  function index() {
    return $this->i;
  }
  
  function size() {
    return count($this->selectors);
  }
  
  function current() {
    return $this->selectors[$this->i];
  }
  
  function key() {
    return $this->i;
  }
  
  function next() {
    $this->i++;
  }
  
  function rewind() {
    $this->i = 0;
  }
  
  function valid() {
    return isset($this->selectors[$this->i]);
  }
  
  function offsetExists($offset) {
    return isset($this->selectors[$offset]);
  }
  
  function offsetGet($offset) {
    return $this->selectors[$offset];
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clSelector objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clSelector objects are read-only.");
  }
  
  function getSelectors() {
    return $this->selectors;
  }
  
  static function generateRegEx() {
    // characters comprising valid names
    // should not contain any of the characters in self::$tokenize
    $name = '[A-Za-z0-9\_\-]+';
    
    // element express with optional index
    $element = "((?P<element>(\\*|{$name}))(\\[(?P<index>[0-9]+)\\])?)";
    
    // attribute expression 
    $attrib = "@(?P<attrib>{$name})";
    
    // tests of equality
    $tests = implode('|', array(
      // Selects elements that have the specified attribute with a value either equal to a given string or starting with that string followed by a hyphen (-).
      "\\|=",
      // Selects elements that have the specified attribute with a value containing the a given substring.
      "\\*=",
      // Selects elements that have the specified attribute with a value containing a given word, delimited by whitespace.
      "~=",
      // Selects elements that have the specified attribute with a value ending exactly with a given string. The comparison is case sensitive.
      "\\$=",
      // Selects elements that have the specified attribute with a value exactly equal to a certain value.
      "=",
      // Select elements that either don't have the specified attribute, or do have the specified attribute but not with a certain value.
      "\\!=",
      // Selects elements that have the specified attribute with a value beginning exactly with a given string.
      "\\^="
    ));
    
    // suffix selectors
    $suffixes = implode('|', array(
      // retun nth element
      ":eq\\([0-9]+\\)",
      // return the first element
      ":first",
      // return the last element
      ":last",
      // greater than index
      ":gt\\([0-9]+\\)",
      // less than index
      ":lt\\([0-9]+\\)",
      // even only
      ":even",
      // odd only
      ":odd",
      // empty - no children, no text
      ":empty",
      // parent - has children: text nodes count
      ":parent",
      // has - contains child element
      ":has\\([^\\)]+\\)",
      // text - text node in the element is
      ":contains\\([^\\)]+\\)"
    ));
    
    $suffix_exp = "(?P<suffix>({$suffixes})+)";
    
    // attribute expression
    self::$attrib_exp = $attrib_exp = "\\[@?((?P<attrib_exp_name>{$name})((?P<test>{$tests})\"(?P<value>.*)\")?)\\]";
    
    // the final expression
    return "#^{$element}?(({$attrib})|(?P<attrib_exp>{$attrib_exp}))*{$suffix_exp}*$#";
  }
  
}

class clNodeArray implements ArrayAccess, Iterator {
  
  private $arr = array();
  private $i;
  
  function __construct($arr = null) {
    if (!is_null($arr)) {
      if ($arr instanceof clNodeArray) {
        $this->arr = $arr->toArray();
      } else {
        $this->arr = $arr;
      }
    }
  }
  
  function toArray() {
    return $this->arr;
  }
  
  function __get($name) {
    if ($node = @$this->arr[0]) {
      return $node->{$name};
    } else {
      return null;
    }
  }
  
  function __call($name, $args) {
    if (($node = @$this->arr[0]) && is_object($node)) {
      return call_user_func_array(array($node, $name), $args);
    } else if (!is_null($node)) {
      throw new Exception("Value in clNodeArray at index 0 is not an object.");
    }
  }
  
  function size() {
    return count($this->arr);
  }
  
  function children() {
    $children = array();
    foreach($this->arr as $node) {
      if (is_object($node)) {
        $children = array_merge($children, $node->children());
      }
    }
    return new clNodeArray($children);
  }
  
  function current() {
    return $this->arr[$this->i];
  }
  
  function key() {
    return $this->i;
  }
  
  function next() {
    $this->i++;
  }
  
  function rewind() {
    $this->i = 0;
  }
  
  function valid() {
    return isset($this->arr[$this->i]);
  }
  
  function offsetExists($offset) {
    if (is_string($offset)) {
      if ($node = @$this->arr[0]) {
        return isset($node[$offset]);
      } else {
        return false;
      }
    } else {
      return isset($this->arr[$offset]);
    }
  }
  
  function offsetGet($offset) {
    if (is_string($offset)) {
      if ($node = @$this->arr[0]) {
        return @$node[$offset];
      } else {
        return null;
      }
    } else {
      return @$this->arr[$offset];
    }
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clNodeArray objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clNodeArray objects are read-only.");
  }
  
  function __toString() {
    if ($node = @$this->arr[0]) {
      return (string) $node;
    } else {
      return '';
    }
  }
  
}

/**
 * Models a discreet unit of data. This unit of data can have attributes (or properties)
 * and children, themselves instances of clNode. Implements ArrayAccess, exposing attribute()
 * function.
 */
abstract class clNode implements ArrayAccess {
  
  /**
   * Factory method: return the correct type of clNode.
   * @param $string The content to parse
   * @param string $type The type - supported include "xml" and "json"
   * @return clNode implementation 
   */
  function getNodeFor($string, $type) {
    if ($type == 'xml') {
      $node = new clXmlNode();
    } else if ($type == 'json') {
      $node = new clJsonNode();
    } else {
      throw new clException("Unsupported Node type: $type");
    }
    
    if (!$node->parse($string)) {
      return false;
    } else {
      return $node;
    }
  }
  
  function offsetExists($offset) {
    $att = $this->attribute($offset);
    return !is_null($att);
  }
  
  function offsetGet($offset) {
    return $this->attribute($offset);
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clNode objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clNode objects are read-only.");
  }
  
  /**
   * Retrieve the first element or attribute queried by $selector.
   * @param string $selector
   * @return mixed an instance of a clNode subclass, or a scalar value
   * @throws clException When an attribute requested does not exist.
   */ 
  function first($selector) {
    $values = $this->get($selector);
    return is_array($values) ? @$values[0] : $values;
  }
  
  /**
   * Retrieve the last element or attribute queried by $selector.
   * @param string $selector
   * @return mixed an instance of a clNode subclass, or a scalar value
   * @throws clException When an attribute requested does not exist.
   */ 
  function last($selector) {
    $values = $this->get($selector);
    return is_array($values) ? @array_pop($values) : $values;
  }
  
  /**
   * Retrieve some data from this Node and/or its children.
   * @param mixed $selector A query conforming to the coreylib selector syntax, or an instance of clSelector
   * @param int $limit A limit on the number of values to return
   * @param array &$results Results from the previous recursive iteration of ::get
   * @return mixed A clNodeArray or a single value, given to $selector.
   */
  function get($selector, $limit = null, &$results = null) {
    // shorten the variable name, for convenience
    $sel = $selector;
    if (!is_object($sel)) {
      $sel = new clSelector($sel);
      if (!$sel->valid()) {
        // nothing to process
        return new clNodeArray();
      }
    }
    
    if (is_null($results)) {
      $results = array($this);
    } else if (!is_array($results)) {
      $results = array($results);
    } 
    
    if ($sel->element) {
      $agg = array();
      foreach($results as $child) {
        if (is_object($child)) {
          $agg = array_merge($agg, $child->children($sel->element));
        }
      }
      $results = $agg;
      
      if (!count($results)) {
        return new clNodeArray();
      }
    } 
    
    if ($sel->attrib) {
      if ($sel->is_expression) {
        $agg = array();
        foreach($results as $child) {
          if ($child->has_attribute($sel->attrib, $sel->test, $sel->value)) {
            $agg[] = $child;
          }
        }
        $results = $agg;
        
      } else {
        $agg = array();
        foreach($results as $child) {
          if (is_object($child)) {
            $att = $child->attribute($sel->attrib);
            if (is_array($att)) {
              $agg = array_merge($agg, $att);
            } else {
              $agg[] = $att;
            }
          }
        }
        
        // remove empty values and reset index
        $agg = array_values(array_filter($agg));
        
        if ($sel->is_attrib_getter) {
          return @$agg[0];
        } else {
          $results = $agg;
        }
      }
      
      if (!count($results)) {
        return new clNodeArray();
      }
    }
    
    if ($sel->suffixes) {
      foreach($sel->suffixes as $suffix => $val) { 
        if ($suffix == 'gt') {
          $results = array_slice($results, $index);
        
        } else if ($suffix == 'lt') {
          $results = array_reverse(array_slice(array_reverse($results), $index));
      
        } else if ($suffix == 'first') {
          $results = array(@$results[0]);
      
        } else if ($suffix == 'last') {
          $results = array(@array_pop($results));
        
        } else if ($suffix == 'eq') {
          $results = array(@$results[$val]);

        } else if ($suffix == 'empty') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (!count($r->children()) && ((string) $r) == '') {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
        
        } else if ($suffix == 'parent') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (((string) $r) != '' || count($r->children())) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'has') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (count($r->children($val))) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'contains') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (strpos((string) $r, $val) !== false) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'even') {
          $agg = array();
          foreach($results as $i => $r) {
            if ($i % 2 === 0) {
              $agg[] = $r;
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'odd') {
          $agg = array();
          foreach($results as $i => $r) {
            if ($i % 2) {
              $agg[] = $r;
            }
          }
          $results = $agg;
          
        }
      }
      
      if (!count($results)) {
        return new clNodeArray();
      }
    }
      
    // recursively use ::get to draw the lowest-level values
    $sel->next();
    if ($sel->valid()) {
      $results = $this->get($sel, null, $results);
    }  
    
    // limit, if requested
    if ($limit && is_array($results)) {
      $results = array_slice($results, 0, $limit);
    }
    
    return new clNodeArray($results);
  }
  
  /**
   * Should return either an array or a single value, given to $selector:
   * if selector is undefined, return an array of all attributes as a 
   * hashtable; otherwise, return the attribute's value, or if the attribute
   * does not exist, return null.
   * @param string $selector
   * @param mixed array, a single value, or null
   */
  protected abstract function attribute($selector = '');
  
  /**
   * Determines if the given $selectors, $tests, and $values are true.
   * @param mixed $selectors a String or an array of strings, matching attributes by name
   * @param mixed $tests a String or an array of strings, each a recognized comparison operator (e.g., = or != or $=)
   * @param mixed $values a String or an array of strings, each a value to be matched according to the corresponding $test
   * @return true when all tests are true; otherwise, false
   */
  protected function has_attribute($selectors = '', $tests = null, $values = null) {
    // convert each parameter to an array
    if (!is_array($selectors)) {
      $selectors = array($selectors);
    }
    if (!is_array($tests)) {
      $tests = array($tests);
    }
    if (!is_array($values)) {
      $values = array($values);
    }
    
    // get all attributes
    $atts = $this->attribute();
    // no attributes? all results false
    if (!count($atts)) {
      return false;
    }
    
    $result = true;
    
    foreach($selectors as $i => $selector) {
      $selected = @$atts[$selector];
      $value = @$values[$i];
      $test = @$tests[$i];
    
      // all tests imply presence
      if (empty($selected)) {
        $result = false;
      // equal
      } else if ($test == '=') {
        $result =  $selected == $value;
      // not equal
      } else if ($test == '!=') {
        $result =  $selected != $value;
      // prefix
      } else if ($test == '|=') {
        $result =  $selected == $value || strpos($selected, "{$value}-") === 0;
      // contains
      } else if ($test == '*=') {
        $result =  strpos($selected, $value) !== false;
      // space-delimited word
      } else if ($test == '~=') {
        $words = preg_split('/\s+/', $selected);
        $result =  in_array($value, $words);
      // ends with
      } else if ($test == '$=') {
        $result =  strpos(strrev($selected), strrev($value)) === 0;
      // starts with
      } else if ($test == '^=') {
        $result =  strpos($selected, $value) === 0;
      }
      
      if ($result == false) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Retrieve a list of the child elements of this node. Unless $direct is true,
   * child elements should include ALL of the elements that appear beneath this element,
   * flattened into a single list, and in document order. If $direct is true,
   * only the direct descendants of this node should be returned.
   * @param string $selector
   * @param boolean $direct (Optional) defaults to false
   * @return array
   */
   
  protected abstract function children($selector = '', $direct = false);
  
  /**
   * Should respond with the value of this node, whatever that is according to
   * the implementation. 
   */
  abstract function __toString();
  
  /**
   * Initialize this node from the data represented by an arbitrary string.
   * @param string $string
   */
  abstract function parse($string = '');
  
}

/**
 * JSON implementation of clNode, wraps the results of json_decode.
 */
class clJsonNode extends clNode {
  
  private $obj;
  
  function __construct(&$json_object = null) {
    $this->obj = $json_object;
  }
  
  function parse($string = '') {
    
  }
  
  protected function children($selector = '', $direct = false) {
    
  }
  
  protected function attribute($selector = '') {
    
  }
  
  function __toString() {
    return '';
  }
  
}

/**
 * XML implementation of clNode, wraps instances of SimpleXMLElement.
 */
class clXmlNode extends clNode {
  
  private $el;
  private $ns;
  private $namespaces;
  private $descendants;
  private $attributes;
  
  /**
   * Wrap a SimpleXMLElement object.
   * @param SimpleXMLElement $simple_xml_el (optional) defaults to null
   * @param clXmlNode $parent (optional) defaults to null
   * @param string $ns (optional) defaults to empty string
   * @param array $namespaces (optional) defaults to null
   */
  function __construct(&$simple_xml_el = null, $parent = null, $ns = '', &$namespaces = null) {
    $this->el = $simple_xml_el;
    $this->parent = $parent;
    $this->ns = $ns;
    
    if (!is_null($namespaces)) {
      $this->namespaces = $namespaces;
    }
    
    if (!$this->namespaces && $this->el) {
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
    }
  }
  
  function parse($string = '') {
    if (($sxe = simplexml_load_string(trim($string))) !== false) {
      $this->el = $sxe;
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
      return true;
    } else {
      // TODO: in PHP >= 5.1.0, it's possible to silence SimpleXML parsing errors and then iterate over them
      // http://us.php.net/manual/en/function.simplexml-load-string.php
      return false;
    }
  }
  
  function namespace() {
    return $this->ns;
  }
  
  function parent() {
    return $this->parent;
  }
  
  /**
   * Expose the SimpleXMLElement API.
   */
  function __call($fx_name, $args) {
    $result = call_user_func_array(array($this->el, $fx_name), $args);
    if ($result instanceof SimpleXMLElement) {
      return new clXmlNode($result, $this, '', $this->namespaces);
    } else {
      return $result;
    }
  }
  
  /**
   * Expose the SimpleXMLElement API.
   */
  function __get($name) {
    $result = $this->el->{$name};
    if ($result instanceof SimpleXMLElement) {
      return new clXmlNode($result, $this, '', $this->namespaces);
    } else {
      return $result;
    }
  }
  
  
  protected function children($selector = '', $direct = false) {    
    if (!$this->descendants) {
      $this->descendants = array();
      foreach($this->namespaces as $ns => $uri) {
        foreach($this->el->children($ns, true) as $child) {
          $node = new clXmlNode($child, $this, $ns, $this->namespaces);
          $this->descendants[] = $node;
          $this->descendants = array_merge($this->descendants, $node->children('*'));
        }
      }
    }
    
    @list($ns, $name) = explode(':', $selector);
    
    if (!$name) {
      $name = $ns;
      $ns = null;
    }
    
    $children = array();
    
    foreach($this->descendants as $child) {
      if ( (!$name || $name == '*' || $child->getName() == $name) && (!$direct || $child->parent() == $this) && (!$ns || $child->ns() == $ns) ) {
        $children[] = $child;
      }
    }
    
    return $children;
  }
  
  
  protected function attribute($selector = '') {
    if (!$this->attributes) {
      $this->attributes = array();
      foreach($this->namespaces as $ns => $uri) {
        $this->attributes[$ns] = $this->el->attributes($ns, true);
      }
    }
    
    @list($ns, $name) = explode(':', $selector);
    
    if (!$name) {
      $name = $ns;
      $ns = null;
    }
    
    // no name? get all.
    if (!$name) {
      $attributes = array();
      foreach($this->attributes as $ns => $atts) {
        foreach($atts as $this_name => $val) {
          if ($ns) {
            $this_name = "$ns:$this_name";
          }
          $attributes[$this_name] = (string) $val;
        }
      }
      return $attributes;
      
    // ns specified? 
    } else if ($ns && isset($this->attributes[$ns])) {
      foreach($this->attributes[$ns] as $this_name => $val) {
        if ($this_name == $name) {
          return (string) $val;
        }
      }
     
    // looking for the name across all namespaces
    } else {
      foreach($this->attributes as $ns => $atts) {
        foreach($atts as $this_name => $val) {
          if ($this_name == $name) {
            return (string) $val;
          }
        }
      }
    }
    
    return null;
  }
  
  /**
   * Use XPATH to select elements. But... why? Ugh.
   * @param 
   * @return clXmlNode
   * @deprecated Use clXmlNode::get($selector, true) instead.
   */
  function xpath($selector) {
    return new clXmlNode($this->el->xpath($selector), $this, '', $this->namespaces);
  }
  
  function __toString() {
    return (string) $this->el;
  }
  
  function info() {
    
  }
  
}