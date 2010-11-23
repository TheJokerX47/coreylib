<?php 
/**
 * coreylib - Core functionality.
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
 * Generic Exception wrapper
 */
class clException extends Exception {}
 
/**
 * Logger.
 */
class clLog {
  
  static function log($message) {
    trigger_error($message, E_USER_NOTICE);
  }
  
  static function warn() {
    trigger_error($message, E_USER_WARN);
  }
  
  static function error() {
    trigger_error($message, E_USER_ERROR);
  }
  
}
 
/**
 * The entry point for all parsing.
 */
class clApi {
  
  const METHOD_GET = 'get';
  const METHOD_POST = 'post';
  
  function __construct($url) {
    
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP GET.
   * @param string $cache_for An expression of time
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function parse($cache_for) {
    
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP POST.
   * @param string $cache_for An expression of time
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function post($cache_for) {
    
  }
  
  /**
   * Print the content of the parsed document.
   */
  function __toString() {
    
  }
  
  function info() {
    
  }
  
  /**
   * Provide access to the wrapped SimpleXML object.
   */
  function __get($prop_name) {
    
  }
  
  /**
   * Provide help to users of older versions.
   */
  function __call($fx_name, $args) {
    
    
  }
  
}

if (!function_exists('coreylib')):
  function coreylib($url, $cache_for = null, $params = array(), $method = clApi::METHOD_GET) {
    $api = new clApi($url);
    
  }
endif;