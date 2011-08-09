<?php
/**
 * Core caching pattern.
 */
abstract class clCache {
 
  /**
   * Get the value stored in this cache, uniquely identified by $cache_key.
   * @param string $cache_key The cache key
   * @param bool $return_raw Instead of returning the cached value, return a packet
   *   of type stdClass, with two properties: expires (the timestamp
   *   indicating when this cached data should no longer be valid), and value
   *   (the unserialized value that was cached there)
   */
  abstract function get($cache_key, $return_raw = false);
  
  /**
   * Update the cache at $cache_key with $value, setting the expiration
   * of $value to a moment in the future, indicated by $timeout.
   * @param string $cache_key Uniquely identifies this cache entry
   * @param mixed $value Some arbitrary value; can be any serializable type
   * @param mixed $timeout An expression of time or a positive integer indicating the number of seconds;
   *   a $timeout of 0 indicates "cache indefinitely."
   * @return a stdClass instance with two properties: expires (the timestamp
   * indicating when this cached data should no longer be valid), and value
   * (the unserialized value that was cached there)
   * @see http://php.net/manual/en/function.strtotime.php
   */
  abstract function set($cache_key, $value, $timeout = 0);
  
  /**
   * Remove from the cache the value uniquely identified by $cache_key
   * @param string $cache_key
   * @return true when the cache key existed; otherwise, false
   */
  abstract function del($cache_key);
  
  /**
   * Remove all cache entries.
   */
  abstract function flush();
  
  /** 
   * Store or retrieve the global cache object.
   */
  static $cache;
  static function cache($cache = null) {
    if (!is_null($cache)) {
      if (!($cache instanceof clCache)) {
        throw new Exception('Object %s does not inherit from clCache', get_class($object));
      }
      self::$cache = new clStash($cache);
    }
    
    if (!self::$cache) {
      try {
        // default is FileCache
        $class = COREYLIB_DEFAULT_CACHE_STRATEGY;
        $cache = new $class();
        self::$cache = new clStash($cache);
      } catch (Exception $e) {
        clApi::log($e, E_USER_WARNING);
        return false;
      }
    }
    
    return self::$cache;
  }

  private static $buffers = array();

  /**
   * Attempt to find some cached content. If it's found, echo
   * the content, and return true. If it's not found, invoke ob_start(),
   * and return false. In the latter case, the calling script should
   * next proceed to generate the content to be cached, then, the
   * script should call clCache::save(), thus caching the content and
   * printing it at the same time.
   * @param string $cache_key
   * @param mixed $cache_for An expression of how long the content 
   * should be cached
   * @param clCache $cache Optionally, a clCache implementation other
   * than the global default
   * @return mixed - see codedoc above
   */
  static function cached($cache_key, $cache_for = -1, $cache = null) {
    $cache = self::cache($cache);

    if ($cached = $cache->get($cache_key, true)) {
      if ($cached->expires != 0 && $cached->expires <= self::time()) {
        self::$buffers[] = (object) array(
          'cache' => $cache,
          'cache_key' => $cache_key,
          'cache_for' => $cache_for
        );
        ob_start();
        return false;
      } else {
        echo $cached->value;
        return true;
      }
    } else {
      self::$buffers[] = (object) array(
        'cache' => $cache,
        'cache_key' => $cache_key,
        'cache_for' => $cache_for
      );
      ob_start();
      return false;
    }
  }

  /**
   * Save the current cache buffer.
   * @see clCache::cached
   */
  static function save($cache_for = null) {
    if ($buffer = array_pop(self::$buffers)) {
      $buffer->cache->set($buffer->cache_key, ob_get_flush(), $cache_for ? $cache_for : $buffer->cache_for);
    } else {
      clApi::log("clCache::save called, but no buffer was open", E_USER_WARNING);
    }   
  }

  /**
   * Cancel the current cache buffer.
   * @see clCache::cached
   */
  static function cancel() {
    if (!array_pop(self::$buffers)) {
      clApi::log("clCache::cancel called, but no buffer was open");
    }
  }

  /**
   * Read data from the global clCache instance.
   */
  static function read($cache_key) {
    $cache = self::cache();
    return $cache->get($cache_key);
  }

  /**
   * Delete content cached in the global default clCache instance.
   */
  static function delete($cache_key) {
    $cache = self::cache();
    $cache->del($cache_key);
  }
  
  /**
   * Write content to the global clCache instance.
   */
  static function write($cache_key, $value, $timeout = -1) {
    $cache = self::cache();
    return $cache->set($cache_key, $value, $timeout);
  }

  /**
   * Convert timeout expression to timestamp marking the moment in the future
   * at which point the timeout (or expiration) would occur.
   * @param mixed $timeout An expression of time or a positive integer indicating the number of seconds
   * @see http://php.net/manual/en/function.strtotime.php
   * @return a *nix timestamp in the future, or the current time if $timeout is 0, always in GMT.
   */
  static function time($timeout = 0) {
    if ($timeout === -1) {
      return false;
    }
    
    if (!is_numeric($timeout)) {
      $original = trim($timeout);
  
      // normalize the expression: should be future
      $firstChar = substr($timeout, 0, 1);
      if ($firstChar == "-") {
        $timeout = substr($timeout, 1);
      } else if ($firstChar != "-") {
        if (stripos($timeout, 'last') === false) {
          $timeout = str_replace('last', 'next', $timeout);
        }
      }
      
      if (($timeout = strtotime(gmdate('c', strtotime($timeout)))) === false) {
        clApi::log("'$original' is an invalid expression of time.", E_USER_WARNING);
        return false;
      }
            
      return $timeout;
    } else {
      return strtotime(gmdate('c'))+$timeout;
    }
  }

  /**
   * Produce a standard cache packet.
   * @param $value to be wrapped
   * @return stdClass
   */
  static function raw(&$value, $expires) {
    return (object) array(
      'created' => self::time(),
      'expires' => $expires,
      'value' => $value
    );
  }
  
}

/**
 * A proxy for another caching system -- stashes the cached
 * data in memory, for fastest possible access. 
 */
class clStash extends clCache {
  
  private $proxied;
  private $mem = array();
  
  function __construct($cache) {
    if (is_null($cache)) {
      throw new clException("Cache object to proxy cannot be null.");
    } else if (!($cache instanceOf clCache)) {
      throw new clException("Cache object must inherit from clCache");
    }
    $this->proxied = $cache;
  }
  
  function get($cache_key, $return_raw = false) {
    if ($stashed = @$this->mem[$cache_key]) {
      // is the stash too old?
      if ($stashed->expires != 0 && $stashed->expires <= self::time()) {
        // yes, stash is too old. try to resource, just in case
        if ($raw = $this->proxied->get($cache_key, true)) {
          // there was something fresher in the proxied cache, to stash it
          $this->mem[$cache_key] = $raw;
          // then return the requested data
          return $return_raw ? $raw : $raw->value;
        // nope... we got nothing
        } else {
          return false;
        }
      // no, the stash was not too old
      } else {
        clApi::log("Cached data loaded from memory [{$cache_key}]");
        return $return_raw ? $stashed : $stashed->value;
      }
    // there was nothing in the stash:
    } else {
      // try to retrieve from the proxied cache:
      if ($raw = $this->proxied->get($cache_key, true)) {
        // there was a value in the proxied cache:
        $this->mem[$cache_key] = $raw;
        return $return_raw ? $raw : $raw->value;
      // nothing in the proxied cache:
      } else {
        return false;
      }
    }
  }
  
  function set($cache_key, $value, $timeout = 0) {
    return $this->mem[$cache_key] = $this->proxied->set($cache_key, $value, $timeout);
  }
  
  function del($cache_key) {
    unset($this->mem[$cache_key]);
    return $this->proxied->del($cache_key);
  }
  
  function flush() {
    $this->mem[] = array();
    $this->proxied->flush();
  }
  
}

/**
 * Caches data to the file system.
 */
class clFileCache extends clCache {
  
  function get($cache_key, $return_raw = false) {
    // seek out the cached data
    if (@file_exists($path = $this->path($cache_key))) {
      // if the data exists, try to load it into memory
      if ($content = @file_get_contents($path)) {
        // if it can be read, try to unserialize it
        if ($raw = @unserialize($content)) {
          // if it's not expired
          if ($raw->expires == 0 || self::time() < $raw->expires) {
            // return the requested data type
            return $return_raw ? $raw : $raw->value;
          // otherwise, purge the file, note the expiration, and move on
          } else {
            @unlink($path);
            clApi::log("Cache was expired [{$cache_key}:{$path}]");
            return false;
          }
        // couldn't be unserialized
        } else {
          clApi::log("Failed to unserialize cache file: {$path}", E_USER_WARNING);
        }
      // data couldn't be read, or the cache file was empty
      } else {
        clApi::log("Failed to read cache file: {$path}", E_USER_WARNING);
      }
    // cache file did not exist
    } else {
      clApi::log("Cache does not exist [{$cache_key}:{$path}]");
      return false;
    }
  }
  
  function set($cache_key, $value, $timeout = 0) {
    // make sure $timeout is valid
    if (($expires = self::time($timeout)) === false) {
      return false;
    }
    
    if ($serialized = @serialize($raw = self::raw($value, $expires))) {
      if (!@file_put_contents($path = $this->path($cache_key), $serialized)) {
        clApi::log("Failed to write cache file: {$path}", E_USER_WARNING);
      } else {
        return $raw;
      }
    } else {
      clApi::log("Failed to serialize cache data [{$cache_key}]", E_USER_WARNING);
      return false;
    }
  }
  
  function del($cache_key) {
    if (@file_exists($path = $this->path($cache_key))) {
      return @unlink($path);
    } else {
      return false;
    }
  }
  
  function flush() {
    if ($dir = opendir($this->basepath)) {
      while($file = readdir($dir)) {
        if (preg_match('#\.coreylib$#', $file)) {
          @unlink($this->basepath . DIRECTORY_SEPARATOR . $file);
        }
      }
      closedir($this->basepath);
    }
  }
  
  private $basepath;
  
  /**
   * @throws clException When the path that is to be the basepath for the cache
   * files cannot be created and/or is not writable.
   */
  function __construct($root = null) {
    if (is_null($root)) {
      $root = realpath(dirname(__FILE__));
    }
    // prepend the coreylib folder
    $root .= DIRECTORY_SEPARATOR . COREYLIB_FILECACHE_DIR;
    // if it doesn't exist
    if (!@file_exists($root)) {
      // create it
      if (!@mkdir($root)) {
        throw new clException("Unable to create File Cache basepath: {$root}");
      }
    } 
    
    // otherwise, if it's not writable
    if (!is_writable($root)) {
      throw new clException("File Cache basepath exists, but is not writable: {$root}");
    }
    
    $this->basepath = $root;
  }
  
  private static $last_path;
  
  /**
   * Generate the file path.
   */
  private function path($cache_key = null) {
    return self::$last_path = $this->basepath . DIRECTORY_SEPARATOR . md5($cache_key) . '.coreylib';
  }
  
  static function getLastPath() {
    return self::$last_path;
  }
  
}

/**
 * Caches data to the WordPress database.
 */
class clWordPressCache extends clCache {
  
  private $wpdb;
  
  function __construct() {
    global $wpdb;
    
    $wpdb->coreylib = $wpdb->prefix.'coreylib';
    
    $wpdb->query("
      CREATE TABLE IF NOT EXISTS $wpdb->coreylib (
        `cache_key` VARCHAR(32) NOT NULL,
        `value` TEXT,
        `expires` DATETIME,
        `created` DATETIME,
        PRIMARY KEY(`cache_key`)
      );
    ");
    
    if (!$wpdb->get_results("SHOW TABLES LIKE '$wpdb->coreylib'")) {
      clApi::log("Failed to create coreylib table for WordPress: {$wpdb->coreylib}");
    } else {
      $this->wpdb =& $wpdb;
    }
  }
  
  function get($cache_key, $return_raw = false) {
    if (!$this->wpdb) {
      return false;
    }
    
    // prepare the SQL
    $sql = $this->wpdb->prepare("SELECT * FROM {$this->wpdb->coreylib} WHERE `cache_key` = %s LIMIT 1", $cache_key);
    // seek out the cached data
    if ($raw = $this->wpdb->get_row($sql)) {
      // convert MySQL date strings to timestamps
      $raw->expires = is_null($raw->expires) ? 0 : strtotime($raw->expires);
      $raw->created = strtotime($raw->created);
      $raw->value = maybe_unserialize($raw->value);
      // if it's not expired
      if (is_null($raw->expires) || self::time() < $raw->expires) {
        // return the requested data type
        return $return_raw ? $raw : $raw->value;
      // otherwise, purge the file, note the expiration, and move on
      } else {
        $this->del($cache_key);
        clApi::log("Cache was expired {$this->wpdb->coreylib}[{$cache_key}]");
        return false;
      }
    
    // cache did not exist
    } else {
      clApi::log("Cache record does not exist {$this->wpdb->coreylib}[{$cache_key}]");
      return false;
    }
  }
  
  function set($cache_key, $value, $timeout = 0) {
    if (!$this->wpdb) {
      return false;
    }
    
    // make sure $timeout is valid
    if (($expires = self::time($timeout)) === false) {
      return false;
    }
    
    // if the value can be serialized
    if ($serialized = maybe_serialize($value)) {
      // prepare the SQL
      $sql = $this->wpdb->prepare("
        REPLACE INTO {$this->wpdb->coreylib} 
        (`cache_key`, `created`, `expires`, `value`) 
        VALUES 
        (%s, %s, %s, %s)
      ", 
        $cache_key,
        $created = date('Y/m/d H:i:s', self::time()),
        $expires = date('Y/m/d H:i:s', $expires),
        $serialized
      );
      
      // insert it!
      $this->wpdb->query($sql);
      if ($this->wpdb->query($sql)) {
        clApi::log("Stored content in {$this->wpdb->coreylib}[{$cache_key}]");
      } else {
        clApi::log("Failed to store content in {$this->wpdb->coreylib}[{$cache_key}]", E_USER_WARNING);
      }
      
      return (object) array(
        'expires' => $expires,
        'created' => $created,
        'value' => value
      );
    } else {
      clApi::log("Failed to serialize cache data [{$cache_key}]", E_USER_WARNING);
      return false;
    }
  }
  
  function del($cache_key) {
    if (!$this->enabled) {
      return false;
    }
    // prepare the SQL
    $sql = $this->wpdb->prepare("DELETE FROM {$this->wpdb->coreylib} WHERE `cache_key` = %s LIMIT 1", $cache_key);
    return $this->wpdb->query($sql);
  }
  
  function flush() {
    if (!$this->wpdb) {
      return false;
    }
    
    $this->wpdb->query("TRUNCATE {$this->wpdb->coreylib}");
  }
  
}

function coreylib_set_cache($cache) {
  clCache::cache($cache);
}

function coreylib_get_cache() {
  return clCache::cache();
}

function coreylib_flush() {
  if ($cache = clCache::cache()) {
    $cache->flush();
  }
}

function cl_cached($cache_key, $cache_for = -1, $cache = null) {
  return clCache::cached($cache_key, $cache_for, $cache);
}

function cl_save($cache_for = null) {
  return clCache::save($cache_for);
}

function cl_cancel() {
  return clCache::cancel();
}

function cl_delete($cache_key) {
  return clCache::delete($cache_key);
}

function cl_read($cache_key) {
  return clCache::read($cache_key);
}

function cl_write($cache_key) {
  return clCache::write($cache_key);
}