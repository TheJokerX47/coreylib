<?php 
/**
 * Generic Exception wrapper
 */
class clException extends Exception {}
 
/**
 * Configuration defaults.
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
// default cache strategy is clFileCache
@define('COREYLIB_DEFAULT_CACHE_STRATEGY', 'clFileCache');
// the name of the folder to create for clFileCache files - this folder is created inside the path clFileCache is told to use
@define('COREYLIB_FILECACHE_DIR', '.coreylib');
// auto-detect WordPress environment?
@define('COREYLIB_DETECT_WORDPRESS', true);

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
  // the download
  private $download;
  // the cache key
  private $cache_key;
  
  /**
   * @param String $url The URL to connect to, with or without query string
   * @param clCache $cache An instance of an implementation of clCache, or null (the default)
   *   to trigger the use of the global caching impl, or false, to indicate that no caching
   *   should be performed.
   */
  function __construct($url, $cache = null) {
    // parse the URL and extract things like user, pass, and query string
    if (( $parts = @parse_url($url) ) && strtolower($parts['scheme']) != 'file') {
      $this->user = @$parts['user'];
      $this->pass = @$parts['pass'];
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
    
    $this->cache = is_null($cache) ? coreylib_get_cache() : $cache;
  }

  function getUrl() {
    return $this->url;
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP GET.
   * @param mixed $cache_for An expression of time (e.g., 10 minutes), or 0 to cache forever, or FALSE to flush the cache, or -1 to skip over all caching (the default)
   * @param string One of clApi::METHOD_GET or clApi::METHOD_POST, or null
   * @param string (optional) Force the node type, ignoring content type signals and auto-detection
   * @return clNode if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function &parse($cache_for = -1, $override_method = null, $node_type = null) {
    $node = false;
    
    if (is_null($this->download)) {
      $this->download = $this->download(false, $cache_for, $override_method);
    }
      
    // if the download succeeded
    if ($this->download->is2__()) {
      if ($node_type) {
        $node = clNode::getNodeFor($this->download->getContent(), $node_type);
      } else if ($this->download->isXml()) {
        $node = clNode::getNodeFor($this->download->getContent(), 'xml');
      } else if ($this->download->isJson()) {
        $node = clNode::getNodeFor($this->download->getContent(), 'json');
      } else {
        throw new clException("Unable to determine content type. You can force a particular type by passing a third argument to clApi->parse(\$cache_for = -1, \$override_method = null, \$node_type = null).");
      }
    } 
      
    return $node;
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
   * Retrieve the content of the parsed document.
   */
  function getContent() {
    return $this->download ? $this->download->getContent() : '';
  }
  
  /**
   * Print the content of the parsed document.
   */
  function __toString() {
    return $this->getContent();
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
   * @param mixed $cache_for One of:
   *    An expression of how long to cache the data (e.g., "10 minutes")
   *    0, indicating cache duration should be indefinite
   *    FALSE to regenerate the cache
   *    or -1 to skip over all caching (the default)
   * @param string $override_method one of clApi::METHOD_GET or clApi::METHOD_POST; optional, defaults to null. 
   * @return clDownload
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function &download($queue = false, $cache_for = -1, $override_method = null) {
    $method = is_null($override_method) ? $this->method : $override_method;
  
    $qs = http_build_query($this->params);
    $url = ($method == self::METHOD_GET ? $this->url.($qs ? '?'.$qs : '') : $this->url);
    
    // use the URL to generate a cache key unique to request and any authentication data present
    $this->cache_key = $cache_key = md5($method.$this->user.$this->pass.$url.$qs);
    if (($download = $this->cacheGet($cache_key, $cache_for)) !== false) {
      return $download;
    }
    
    // TODO: implement file:// protocol here
    
    $this->ch = curl_init($url);
    
    // authenticate?
    if ($this->user) {
      curl_setopt($this->ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
      curl_setopt($this->ch, CURLOPT_USERPWD, "$this->user:$this->pass");
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
    
    curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
    
    if ($this->method != self::METHOD_POST) {
      curl_setopt($this->ch, CURLOPT_HTTPGET, true);
    } else {
      curl_setopt($this->ch, CURLOPT_POST, true);
      curl_setopt($this->ch, CURLOPT_POSTFIELDS, $this->params);
    }
    
    if ($queue) {
      $download = new clDownload($this->ch, false);
      
    } else {
      $content = curl_exec($this->ch);
      $download = new clDownload($this->ch, $content);
      
      // cache?
      if ($download->is2__()) {
        $this->cacheSet($cache_key, $download, $cache_for);
      }
    }
    
    return $download;
  }
  
  function setDownload(&$download) {
    if (!($download instanceof clDownload)) {
      throw new Exception('$download must be of type clDownload');
    }
    
    $this->download = $download;
  }
  
  function cacheWith($clCache) {
    $this->cache = $clCache;
  }
  
  function cacheGet($cache_key, $cache_for = -1) {
    if (!$this->cache || COREYLIB_NOCACHE || $cache_for === -1 || $cache_for === false) {
      return false;
    }
    return $this->cache->get($cache_key);
  }
  
  function cacheSet($cache_key, $download, $cache_for = -1) {
    if (!$this->cache || COREYLIB_NOCACHE || $cache_for === -1) {
      return false;
    } else {
      return $this->cache->set($cache_key, $download, $cache_for);
    }
  }

  /**
   * Delete cache entry for this API.
   * Note that the cache key is generated from several components of the request,
   * including: the request method, the URL, the query string (parameters), and
   * any username or password used. Changing any one of these before executing
   * this function will modify the cache key used to store/retrieve the cached
   * response. So, make sure to fully configure your clApi instance before running 
   * this method.
   * @param string $override_method For feature parity with clApi->parse, allows
   * for overriding the HTTP method used in cache key generation. 
   * @return A reference to this clApi instance (to support method chaining)
   */
  function &flush($override_method = null) {
    $method = is_null($override_method) ? $this->method : $override_method;
    $qs = http_build_query($this->params);
    $url = ($method == self::METHOD_GET ? $this->url.($qs ? '?'.$qs : '') : $this->url);
    // use the URL to generate a cache key unique to request and any authentication data present
    $cache_key = md5($method.$this->user.$this->pass.$url.$qs);
    $this->cacheDel($cache_key);

    return $this;
  }
  
  function cacheDel($cache_key = null) {
    if (!$this->cache || COREYLIB_NOCACHE) {
      return false;
    } else {
      return $this->cache->del($cache_key);
    }
  }
  
  function getCacheKey() {
    return $this->cache_key;
  }
  
  function &getDownload() {
    return $this->download;
  }

  static $sort_by = null;

  /**
   * Given a collection of clNode objects, use $selector to query a set of nodes
   * from each, then (optionally) sort those nodes by one or more sorting filters.
   * Sorting filters should be specified <type>:<selector>, where <type> is one of
   * str, num, date, bool, or fx and <selector> is a valid node selector expression.
   * The value at <selector> in each node will be converted to <type>, and the 
   * collection will then be sorted by those converted values. In the special case
   * of fx, <selector> should instead be a callable function. The function (a custom)
   * sorting rule, should be implemented as prescribed by the usort documentation,
   * and should handle node value selection internally.
   * @param mixed $apis array(clNode), an array of stdClass objects (the return value of clApi::exec), a single clNode instance, or a URL to query
   * @param string $selector
   * @param string $sort_by
   * @return array(clNode) A (sometimes) sorted collection of clNode objects
   * @see http://www.php.net/manual/en/function.usort.php
   */
  static function &grep($nodes, $selector, $sort_by = null /* dynamic args */) {
    $args = func_get_args();
    $nodes = @array_shift($args);

    if (!$nodes) {
      return false;

    } else if (!is_array($nodes)) {
      if ($nodes instanceof clNode) {
        $nodes = array($nodes);
      } else {
        $api = new clApi((string) $nodes);
        if ($node = $api->parse()) {
          clApi::log("The URL [$nodes] did not parse, so clApi::grep fails.", E_USER_ERROR);
          return false;
        }
        $nodes = array($node);
      }
    }

    $selector = @array_shift($args);

    if (!$selector) {
      clApi::log('clApi::grep requires $selector argument (arg #2)', E_USER_WARNING);
      return false;
    }

    $sort_by = array();

    foreach($args as $s) {
      if (preg_match('/(.*?)\:(.*)/', $s, $matches)) {
        @list($type, $order) = preg_split('/,\s*/', $matches[1]);
        if (!$order) {
          $order = 'asc';
        }
        $sort_by[] = (object) array(
          'type' => $type,
          'order' => strtolower($order),
          'selector' => $matches[2] 
        );
      } else {
        clApi::log("clApi::grep $sort_by arguments must be formatted <type>:<selector>: [{$s}] is invalid.", E_USER_WARNING);
      }
    }

    // build the node collection
    $grepd = array();
    foreach($nodes as $node) {
      // automatically detect clApi::exec results...
      if ($node instanceof stdClass) {
        if ($node->parsed) {
          $grepd = array_merge( $grepd, $node->parsed->get($selector)->toArray() );
        } else {
          clApi::log(sprintf("clApi::grep can't sort failed parse on [%s]", $node->api->getUrl()), E_USER_WARNING);
        }
      } else {
        $grepd = array_merge( $grepd, $node->get($selector)->toArray() );
      }
    }

    // sort the collection
    foreach($sort_by as $s) {
      self::$sort_by = $s;
      usort($grepd, array('clApi', 'grep_sort'));
      if ($order == 'desc') {
        $grepd = array_reverse($grepd);
      }
    }

    return $grepd;
  }

  static function grep_sort($node1, $node2) {
    $sort_by = self::$sort_by;
    $v1 = $node1->get($sort_by->selector);
    $v2 = $node2->get($sort_by->selector);

    if ($sort_by->type == 'string') {
      $v1 = (string) $v1;
      $v2 = (string) $v2;
      return strcasecmp($v1, $v2);

    } else if ($sort_by->type == 'bool') {
      $v1 = (bool) (string) $v1;
      $v2 = (bool) (string) $v2;
      return ($v1 === $v2) ? 0 : ( $v1 === true ? -1 : 1 );

    } else if ($sort_by->type == 'num') {
      $v1 = (float) (string) $v1;
      $v2 = (float) (string) $v2;
      return ($v1 === $v2) ? 0 : ( $v1 < $v2 ? -1 : 1 );

    } else if ($sort_by->type == 'date') {
      $v1 = strtotime((string) $v1);
      $v2 = strtotime((string) $v2);
      return ($v1 === $v2) ? 0 : ( $v1 < $v2 ? -1 : 1 );

    }
  }
  
  /**
   * Use curl_multi to execute a collection of clApi objects.
   */
  static function exec($apis, $cache_for = -1, $override_method = null, $node_type = null) {
    $mh = curl_multi_init();
    
    $handles = array();
    
    foreach($apis as $a => $api) {
      if (is_string($api)) {
        $api = new clApi($api);
        $apis[$a] = $api;
      } else if (!($api instanceof clApi)) {
        throw new Exception("clApi::exec expects an Array of clApi objects.");
      }
      
      $download = $api->download(true, $cache_for, $override_method);
      $ch = $download->getCurl();
      
      if ($download->getContent() === false) {
        curl_multi_add_handle($mh, $ch);
      } else {
        $api->setDownload($download);
      }
      
      $handles[(int) $ch] = array($api, $download, $ch);
    }
    
    do {
      $status = curl_multi_exec($mh, $active);
    } while($status == CURLM_CALL_MULTI_PERFORM || $active);
    
    foreach($handles as $ch => $ref) {
      list($api, $download, $ch) = $ref;
      
      // update the download object with content and CH info 
      $download->update(curl_multi_getcontent($ch), curl_getinfo($ch));
      
      // if the download was a success
      if ($download->is2__()) {
        // cache the download
        $api->cacheSet($api->getCacheKey(), $download, $cache_for);
      }
      
      $api->setDownload($download);
    }
    
    $results = array();
    
    foreach($apis as $api) {
      $results[] = (object) array(
        'api' => $api,
        'parsed' => $api->parse($cache_for = -1, $override_method = null, $node_type = null)
      );
    }
    
    curl_multi_close($mh);
    
    return $results;
  }
  
  /**
   * Print $msg to the error log.
   * @param mixed $msg Can be a string, or an Exception, or any other object
   * @param int $level One of the E_USER_* error level constants.
   * @return string The value of $msg, post-processing
   * @see http://www.php.net/manual/en/errorfunc.constants.php
   */
  static function log($msg, $level = E_USER_NOTICE) {
    if ($msg instanceof Exception) {
      $msg = $msg->getMessage();
    } else if (!is_string($msg)) {
      $msg = print_r($msg, true);
    }

    if ($level == E_USER_NOTICE && !COREYLIB_DEBUG) {
      // SHHH...
      return $msg;
    }
    
    trigger_error($msg, $level);
    
    return $msg;
  }
  
}

if (!function_exists('coreylib')):
  function coreylib($url, $cache_for = -1, $params = array(), $method = clApi::METHOD_GET) {
    $api = new clApi($url);
    $api->param($params);
    if ($node = $api->parse($cache_for, $method)) {
      return $node;
    } else {
      return false;
    }
  }
endif;

class clDownload {
  
  private $content = '';
  private $ch;
  private $info;
  
  function __construct(&$ch = null, $content = false) {
    $this->ch = $ch;
    $this->info = curl_getinfo($this->ch);
    $this->content = $content;
  }
  
  function __sleep() {
    return array('info', 'content');
  }
 
  function getContent() {
    return $this->content;
  }
  
  function update($content, $info) {
    $this->content = $content;
    $this->info = $info;
  }
  
  function hasContent() {
    return (bool) strlen(trim($this->content));
  }
  
  function &getCurl() {
    return $this->ch;
  }
  
  function getInfo() {
    return $this->info;
  }
  
  private static $xmlContentTypes = array(
    'text/xml',
    'application/rss\+xml',
    'xml'
  );
  
  function isXml() {
    if (preg_match(sprintf('#(%s)#i', implode('|', self::$xmlContentTypes)), $this->info['content_type'])) {
      return true;
    } else if (stripos(trim($this->content), '<?xml') === 0) {
      return true;
    } else {
      return false;
    }
  }
  
  private static $jsonContentTypes = array(
    'text/javascript',
    'application/x-javascript',
    'application/json',
    'text/x-javascript',
    'text/x-json',
    '.*json.*'
  );
  
  function isJson() {
    if (preg_match(sprintf('#(%s)#i', implode('|', self::$jsonContentTypes)), $this->info['content_type'])) {
      return true;
    } else if (substr(trim($this->content), 0) === '{' && substr(trim($this->content), -1) === '}') {
      return true;
    } else if (substr(trim($this->content), 0) === '[' && substr(trim($this->content), -1) === ']') {
      return true;
    } else {
      return false;
    }
  }
  
  function __call($name, $args) {
    if (preg_match('/^is(\d+)(_)?(_)?$/', $name, $matches)) {
      $status = $this->info['http_code'];
      
      if (!$status) {
        return false;
      }
      
      $http_status_code = $matches[1];
      $any_ten = @$matches[2];
      $any_one = @$matches[3];
      
      if ($any_ten || $any_one) {
        for($ten = 0; $ten <= ($any_ten ? 0 : 90); $ten+=10) {
          for($one = 0; $one <= (($any_ten || $any_one) ? 0 : 9); $one++) {
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