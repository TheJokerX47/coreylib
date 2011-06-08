<?php 
/**
 * Generic Exception wrapper
 */
class clException extends Exception {}
 
/**
 * Configuration settings.
 */
// enable debugging output
@define('COREYLIB_DEBUG', false);
// maximum number of times to retry downloading content before failure
@define('COREYLIB_MAX_DOWNLOAD_ATTEMPTS', 3);
// the number of seconds to wait before timing out on CURL requests
@define('COREYLIB_DEFAULT_TIMEOUT', 30);
// the default HTTP method for requesting data from the URL
@define('COREYLIB_DEFAULT_METHOD', 'get');
// set this to true to disable all caching activity
@define('COREYLIB_NOCACHE', false);

/**
 * Coreylib core.
 */
class clApi {
  
  // request method
  const METHOD_GET = 'get';
  const METHOD_POST = 'post';
  private $method;
  
  // the URL provided in the constructor
  private $url;
  // the content we're parsing
  private $content;
  // default HTTP headers
  private $headers = array(
    
  );
  // default curlopts
  private $curlopts = array(
    CURLOPT_USERAGENT => 'coreylib/2.0',
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false
  );
  // the parameters being passed in the request
  private $params = array();
  // basic authentication 
  private $user;
  private $pass;
  // the cURL handle used to get the content
  private $ch;
  // reference to caching strategy
  private $cache;
  
  /**
   * @param String $url The URL to connect to, with or without query string
   */
  function __construct($url) {
    // parse the URL and extract things like user, pass, and query string
    if (( $parts = @parse_url($url) ) && strtolower($parts['scheme']) != 'file') {
      $this->user = @$parts['user'];
      $this->pass = @$parts['path'];
      @parse_str($parts['query'], $this->params);
      // rebuild $url
      $url = sprintf('%s://%s%s', 
        $parts['scheme'], 
        $parts['host'] . ( @$parts['port'] ? ':'.$parts['port'] : '' ),
        $parts['path'] . ( @$parts['fragment'] ? ':'.$parts['fragment'] : '')
      );
    }
    // stash the processed $url
    $this->url = $url;
    // setup the default request method
    $this->method = ($method = strtolower(COREYLIB_DEFAULT_METHOD)) ? $method : self::METHOD_GET;
    
    $this->curlopt(CURLOPT_CONNECTTIMEOUT, COREYLIB_DEFAULT_TIMEOUT);
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP GET.
   * @param mixed $cache_for An expression of time (e.g., 10 minutes), or 0 to cache forever, or FALSE to flush the cache, or -1 to skip over all caching (the default)
   * @param string One of clApi::METHOD_GET or clApi::METHOD_POST, or null
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function parse($cache_for = -1, $override_method = null) {
    
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP POST.
   * @param mixed $cache_for An expression of time (e.g., 10 minutes), or 0 to cache forever, or FALSE to flush the cache, or -1 to skip over all caching (the default)
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   * @deprecated Use clApi->parse($cache_for, clApi::METHOD_POST) instead.
   */
  function post($cache_for = -1) {
    return $this->parse($cache_for, self::METHOD_POST);
  }
  
  /**
   * Print the content of the parsed document.
   */
  function __toString() {
    return ($this->content ? $this->content : '');
  }
  
  /**
   * Set or get a coreylib configuration setting.
   * @param mixed $option Can be either a string or an array of key/value configuration settings
   * @param mixed $value The value to assign
   * @return mixed If $value is null, then return the value stored by $option; otherwise, null.
   */
  static function setting($option, $value = null) {
    if (!is_null($value) || is_array($option)) {
      if (is_array($option)) {
        self::$options = array_merge(self::$options, $option);
      } else {
        self::$options[$option] = $value;
      }
    } else {
      return @self::$options[$option];
    }
  }
  
  function info() {
    
  }
  
  /**
   * Set or get an HTTP header configuration
   * @param mixed $name Can be either a string or an array of key/value pairs
   * @param mixed $value The value to assign
   * @return mixed If $value is null, then return the value stored by $name; otherwise, null.
   */
  function header($name, $value = null) {
    if (!is_null($value) || is_array($name)) {
      if (is_array($name)) {
        $this->headers = array_merge($this->headers, $name);
      } else {
        $this->headers[$name] = $value;
      }
    } else {
      return @$this->headers[$name];
    }
  }
  
  /**
   * Set or get a request parameter
   * @param mixed $name Can be either a string or an array of key/value pairs
   * @param mixed $value The value to assign
   * @return mixed If $value is null, then return the value stored by $name; otherwise, null.
   */
  function param($name, $value = null) {
    if (!is_null($value) || is_array($name)) {
      if (is_array($name)) {
        $this->params = array_merge($this->params, $name);
      } else {
        $this->params[$name] = $value;
      }
    } else {
      return @$this->params[$name];
    }
  }
  
  /**
   * Set or get a CURLOPT configuration
   * @param mixed $opt One of the CURL option constants, or an array of option/value pairs
   * @param mixed $value The value to assign
   * @return mixed If $value is null, then return the value stored by $opt; otherwise, null.
   */
  function curlopt($opt, $value = null) {
    if (!is_null($value) || is_array($opt)) {
      if (is_array($opt)) {
        $this->curlopts = array_merge($this->curlopts, $opt);
      } else {
        $this->curlopts[$opt] = $value;
      }
    } else {
      return @$this->curlopts[$opt];
    }
  }
  
  /**
   * Download the content according to the settings on this object, or load from the cache.
   * @param bool $queue If true, setup a CURL connection and return the handle; otherwise, execute the handle and return the content
   * @param mixed $cache_for An expression of time (e.g., 10 minutes), or 0 to cache forever, or FALSE to flush the cache, or -1 to skip over all caching (the default)
   * @param string $override_method one of clApi::METHOD_GET or clApi::METHOD_POST; optional, defaults to null. 
   * @return clDownload
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function &download($queue = false, $cache_for = -1, $override_method = null) {
    $method = is_null($override_method) ? $this->method : $override_method;
  
    $qs = http_build_query($this->params);
    if ($method != self::METHOD_POST) {
      $url = ($method == self::METHOD_GET ? $this->url.($qs ? '?'.$qs : '') : $this->url);
    }
    
    // use the URL to generate a cache key
    $cache_key = md5($method.$url.$qs);
    if (($download = $this->cacheGet($cache_key, $cache_for)) !== false) {
      return $download;
    }
    
    // TODO: implement File-based and Facebook-based content aqusition here
    $this->ch = curl_init($url);
    
    // authenticate?
    if ($this->username) {
      curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
      curl_setopt($this->ch, CURLOPT_USERPWD, "$this->username:$this->password");
    }
    
    // set headers
    $headers = array();
    foreach($this->headers as $name => $value) {
      $headers[] = "{$name}: {$value}";
    }
    curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
    
    // apply pre-set curl opts, allowing some (above) to be overwritten
    foreach($this->curlopts as $opt => $val) {
      curl_setopt($this->ch, $opt, $val);
    }
    
    if (!$queue) {
      curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
    }
    
    if ($this->method != self::METHOD_POST) {
      curl_setopt($this->ch, CURLOPT_HTTPGET, true);
    } else {
      curl_setopt($this->ch, CURLOPT_POST, true);
      curl_setopt($this->ch, CURLOPT_POSTFIELDS, $this->params);
    }
    
    if ($queue) {
      return new clDownload($this->ch, null);
    } else {
      $content = curl_exec($this->ch);
      $download = new clDownload($this->ch, $content);
      
      // cache?
      if ($download->is2__()) {
        $this->cacheSet($cache_key, $cache_for, $download);
      }
      
      return $download;
    }
  }
  
  function cacheWith($clCache) {
    $this->cache = $clCache;
  }
  
  function cacheGet($cache_key, $cache_for = -1) {
    if (!$this->cache || COREYLIB_NOCACHE || $cache_for === -1 || $cache_for === false) {
      return false;
    }
    return $this->cache->get($cache_key, $cache_for);
  }
  
  function cacheSet($cache_key, $cache_for, $download) {
    if (!$this->cache || COREYLIB_NOCACHE || $cache_for === -1 || $cache_for === false) {
      return false;
    } else {
      return $this->cache->set($cache_key, $cache_for, $download);
    }
  }
  
  function cacheDel($cache_key = null) {
    if (!$this->cache || COREYLIB_NOCACHE) {
      return false;
    } else {
      return $this->cache->del($cache_key);
    }
  }
  
  /**
   * Print $msg to the error log.
   * @param mixed $msg Can be a string, or an Exception, or any other object
   * @param int $level One of the E_USER_* error level constants.
   * @return string The value of $msg, post-processing
   * @see http://www.php.net/manual/en/errorfunc.constants.php
   */
  static function log($msg, $level = E_USER_NOTICE) {
    if (is_a($msg, 'Exception')) {
      $msg = $msg->getMessage();
    } else if (!is_string($msg)) {
      $msg = print_r($msg, true);
    }
    
    trigger_error($msg, $level);
    
    return $msg;
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
  function coreylib($url, $cache_for = -1, $params = array(), $method = clApi::METHOD_GET) {
    $api = new clApi($url);
    $api->param($params);
    if ($api->parse($cache_for, $method)) {
      return $api;
    } else {
      return false;
    }
  }
endif;

class clDownload {
  
  private $content;
  private $ch;
  
  function __construct(&$ch = null, $content = null) {
    $this->ch = $ch;
    $this->content = $content;
  }
 
  function getContent() {
    return $this->content;
  }
  
  function getCurl() {
    return $this->ch;
  }
  
  function isXml() {
    
  }
  
  function isJson() {
    
  }
  
  function __call($name, $args) {
    if (preg_match('/^is(\d+)(_)?(_)?$/', $name, $matches)) {
      $status = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
      
      if (!$status) {
        return false;
      }
      
      $http_status_code = $matches[1];
      $any_ten = (bool) @$matches[2];
      $any_one = (bool) @$matches[3];
      
      if ($any_ten || $any_one) {
        for($ten = 0; $ten <= $any_ten ? 0 : 90; $ten+=10) {
          for($one = 0; $one <= $any_ten || $any_one ? 0 : 9; $one++) {
            $code = $http_status_code . ($ten == 0 ? '0' : '') . ($ten + $one);
            if ($code == $status) {
              return true;
            }
          }
        }
      } else if ($status == $http_status_code) {
        return true;
      } else {
        return false;
      }
    } else {
      throw new clException("Call to unknown function: $name");
    }
  }
  
}