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

abstract class clNode {
  
  const REGEX_ATTRIBUTE = '/^@(.*)?$/';
  const REGEX_ARRAY_ATTRIBUTE = '/(.*)\[(\d+)\](@(.*))?$/';
  const REGEX_ELEMENT_ATTRIBUTE = '/([^@]+)(@(.*))?$/';
  
  /**
   * Factory method: return the correct type of clNode.
   * @param $string The content to parse
   * @param string $type The type - supported include "xml" and "json"
   * 
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
   * Retrieve some data from this Node or its children.
   * @param string $selector A query conforming to the coreylib selector syntax.
   * @param int $limit A limit on the number of values to return
   * @return mixed An array or a single value, given to $selector
   * @throws clException When an attribute requested does not exist.
   */
  function get($selector, $limit = null) {
    $selectors = explode('/', $selector);
    $this_selector = array_shift($selectors);
    
    $sel = null;
		$index = null;
		$attribute = null;

    // $sel is just an attribute, like "@foo"
		if (preg_match(self::REGEX_ATTRIBUTE, $this_selector, $matches)) { 
			$attribute = $matches[1];
		
		// $sel is an array spec and, optionally, includes an attribute
		// like foo[1]
		// like foo[1]@bar
		} else if (preg_match(self::REGEX_ARRAY_ATTRIBUTE, $this_selector, $matches)) { 
			$sel = $matches[1];	
			$index = (int) $matches[2];	
			$attribute = (isset($matches[4])) ? $matches[4] : null;
			
		// $sel is an element and, optionally, includes an attribute
		// like foo
		// like foo@bar
		} else if (preg_match(self::REGEX_ELEMENT_ATTRIBUTE, $this_selector, $matches)) { 
			$sel = $matches[1];
			$attribute = (isset($matches[3])) ? $matches[3] : null;
		}
		
		
		// should we be looking for an element?
	  if ($sel) {
	    $children = $this->children($sel);
	    
	    if (!count($children)) {
        return $limit == 1 ? null : array();
      }
	    
      // validate $index
	    if ($index && $index > count($children)-1) {
	      return null;
	    
	    // implement $index: we can return only one result
	    } else if ($index !== null) {
	      $child = @$children[$index];
	      
        if (count($selectors)) {
          return $child->get(implode('/', $selectors));
        } else {
          if ($attribute) {
  	        return $child->attribute($attribute);
          } else {
            return $child;
          }
        }
  	    
	    // index is not defined: we can return an array
	    } else {
	      // there's more to select
	      if (count($selectors)) {
	        
	        // aggregate the results

	        
	      // there's nothing more to select
	      } else {
	        
	        if ($attribute) {
	          $atts = array();
            foreach($children as $child) {
              $atts[] = $child->attribute($attribute);
              if ($limit && count($atts) > $limit) {
                break;
              }
            }
            
            return $atts;
	          
	        } else {
	          if ($limit) {
	            $children = array_slice($children, 0, $limit);
	          }
	          
	          return $children;
	        }
	      }
	    }
	    
	  // no element: just an attribute spec  
	  } else if ($attribute) {
	    return $this->attribute($attribute);
	  }
	}
  
  protected abstract function attribute($selector = '');
  
  protected abstract function children($selector = '');
  
  abstract function __toString();
  
  abstract function parse($string = '');
  
}

//class clJsonNode extends clNode {}

class clXmlNode extends clNode {
  
  private $el;
  public $parent;
  private $ns;
  public $namespaces;
  
  /**
   * Wrap a SimpleXMLElement object.
   * @param SimpleXMLElement $simple_xml_el
   * @param array $namespaces (optional)
   */
  function __construct(&$simple_xml_el = null, $ns = '', &$namespaces = null) {
    $this->el = $simple_xml_el;
    $this->ns = $ns;
    $this->namespaces = $namespaces;
    
    if (!$this->namespaces && $this->el) {
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
    }
  }
  
  function parse($string = '') {
    if ($sxe = simplexml_load_string($string)) {
      $this->el = $sxe;
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
      return true;
    } else {
      // TODO: in PHP >= 5.1.0, it's possible to silence errors and then iterate over them
      // http://us.php.net/manual/en/function.simplexml-load-string.php
      return false;
    }
  }
  
  /**
   * Expose the SimpleXMLElement API.
   */
  function __call($fx_name, $args) {
    $result = call_user_func_array(array($this->el, $fx_name), $args);
    if ($result instanceof SimpleXMLElement) {
      return new clXmlNode($result, $this);
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
      return new clXmlNode($result, $this);
    } else {
      return $result;
    }
  }
  
  private $children;
  
  /**
   * Retrieve children of this node named $selector. The benefit
   * of this over SimpleXMLElement::children() is that this method
   * is namespace agnostic, searching available children until
   * matches are found.
   * @param string $selector A name, e.g., "foo", or a namespace-prefixed name, e.g., "me:foo"
   * @return array of clXmlNodes, when found; otherwise, empty array
   */
  protected function children($selector = '') {
    if (!$this->children) {
      $this->children = array();
      foreach($this->namespaces as $ns => $uri) {
        $this->children[$ns] = &$this->el->children($ns, true);
      }
    }
  
    @list($ns, $name) = explode(':', $selector);
    
    if (!$name) {
      $name = $ns;
      $ns = null;
    }
    
    $children = array();
    
    // no namespace and no name? get all.
    if (!$ns && !$name) {
      foreach($this->children as $ns => $child_sxe) {
        foreach($child_sxe as $child) {
          $children[] = new clXmlNode($child, $ns, $this->namespaces);
        }
      }
      return $children;
      
    // ns specified?
    } else if ($ns && isset($this->children[$ns])) {
      foreach($this->children[$ns] as $child) {
        if ($child->getName() == $name) {
          $children[] = new clXmlNode($child, $this, $ns);
        }
      }
    
    // looking for the name across all namespaces
    } else {
      foreach($this->children as $ns => $child_sxe) {
        foreach($child_sxe as $child) {
          if ($child->getName() == $name) {
            $children[] = new clXmlNode($child, $ns, $this->namespaces);
          }
        }
      }
    }
    
    return $children;
  }
  
  private $attributes;
  
  /**
   * Retrieve attributes of this node named $selector. The benefit
   * of this over SimpleXMLElement::attributes() is that this method
   * is namespace agnostic, searching available attributes until
   * matches are found.
   * @param string $selector A name, e.g., "foo", or a namespace-prefixed name, e.g., "me:foo"
   * @return mixed a scalar value when $selector is defined; otherwise, an array of all attributes and values
   * @throws clException When $selector is defined and attribute is not found
   */
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
    
    // no namespace and no name? get all.
    if (!$ns && !$name) {
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
     
      throw new clException(sprintf("[%s:%s] attribute not found in [%s]", $ns, $name, $this->getName()));
    
    // looking for the name across all namespaces
    } else {
      foreach($this->attributes as $ns => $atts) {
        foreach($atts as $this_name => $val) {
          if ($this_name == $name) {
            return (string) $val;
          }
        }
      }
      
      throw new clException(sprintf("[%s] attribute not found in [%s]", $name, $this->getName()));
    }
  }
  
  /**
   * Use XPATH to select elements. But... why? Ugh.
   * @param 
   * @return clXmlNode
   * @deprecated Use clXmlNode::get($selector, true) instead.
   */
  function xpath($selector) {
    return new clXmlNode($this->el->xpath($selector));
  }
  
  function __toString() {
    return (string) $this->el;
  }
  
  function info() {
    
  }
  
}