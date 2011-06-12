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
   * Store or retrieve the global cache object.
   */
  static $cache;
  static function cache($cache = null) {
    if (!is_null($cache)) {
      if (!is_a($cache, 'clCache')) {
        throw new Exception('Object %s does not inherit from clCache', get_class($object));
      }
      self::$cache = $cache;
    }
    
    if (!self::$cache) {
      try {
        // default is FileCache
        self::$cache = new clFileCache();
      } catch (Exception $e) {
        clApi::log($e, E_USER_WARNING);
        return false;
      }
    }
    
    return self::$cache;
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
        clApi::log("Cached data loaded from runtime stack [{$cache_key}]");
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
    $sql = $this->wpdb->prepare("SELECT * FROM $wpdb->coreylib WHERE `cache_key` = ? LIMIT 1", $cache_key);
    // seek out the cached data
    if ($raw = $this->wpdb->get_row($sql)) {
      // convert MySQL date strings to timestamps
      $raw->expires = is_null($raw->expires) ? 0 : strtotime($raw->expires);
      $raw->created = strtotime($raw->created);
      // if it can be read, try to unserialize it
      if ($raw->value = @unserialize($raw->value)) {
        // if it's not expired
        if (is_null($raw->expires) || self::time() < strtotime($raw->expires)) {
          // return the requested data type
          return $return_raw ? $raw : $raw->value;
        // otherwise, purge the file, note the expiration, and move on
        } else {
          $this->del($cache_key);
          clApi::log("Cache was expired [{$cache_key}]");
          return false;
        }
      // couldn't be unserialized
      } else {
        clApi::log("Failed to unserialize cached data [{$cache_key}]", E_USER_WARNING);
      }
    // cache did not exist
    } else {
      clApi::log("Cache record does not exist [{$cache_key}]");
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
    
    if ($serialized = @serialize($raw = self::raw($value, $expires))) {
      // prepare the SQL
      $sql = $this->wpdb->prepare("
        REPLACE INTO $wpdb->coreylib 
        (`cache_key`, `created`, `expires`, `value`) 
        VALUES 
        (?, ?, ?, ?)
      ", 
        $cache_key,
        strtotime('Y/m/d H:i:s', $raw->created),
        strtotime('Y/m/d H:i:s', $raw->expires),
        $serialized
      );
      
      $this->wpdb->query($sql);
      // TODO: test for failures
      return $raw;
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
    $sql = $this->wpdb->prepare("DELETE FROM $wpdb->coreylib WHERE `cache_key` = ? LIMIT 1", $cache_key);
    return $this->wpdb->query($sql);
  }
  
}

function coreylib_set_cache($cache) {
  clCache::cache($cache);
}

function coreylib_get_cache() {
  return clCache::cache();
}