<?php
/**
 * These next few lines allow coreylib.php to be dropped into your plugins folder.
 * Doing so will automatically configure it to use the WordPress database for cache storage.
 * You can override the cache system by setting COREYLIB_DETECT_WORDPRESS to false in your
 * wp-config.php, or by calling coreylib_set_cache(clCache) at any time to override.
 */
if (COREYLIB_DETECT_WORDPRESS) {
  // if the add_action function is present, assume this is wordpress
  if (function_exists('add_action')) {
    function init_coreylib_cache() {
      coreylib_set_cache(new clWordPressCache());
    }
    add_action('init', 'init_coreylib_cache');
  }
}