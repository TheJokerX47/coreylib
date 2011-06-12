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
    // override default caching mechanism with clWordPressCache
    function coreylib_init_cache() {
      coreylib_set_cache(new clWordPressCache());
      add_filter(sprintf('plugin_action_links_%s', basename(__FILE__)), 'coreylib_plugin_action_links', 10, 4);
      add_action('wp_ajax_coreylib_clear_cache', 'coreylib_wordpress_flush');
    }
    
    add_action('init', 'coreylib_init_cache');
    
    // allow for flushing global cache by WP ajax call
    function coreylib_wordpress_flush() {
      if (current_user_can('edit_plugins')) {
        coreylib_flush();
      }
      exit;
    }
    
    // add the cache flushing link to the plugins screen
    function coreylib_plugin_action_links($actions, $plugin_file, $plugin_data, $context) {
      $actions['flush'] = '<a href="#" onclick="if (confirm(\'Are you sure you want to clear the coreylib cache?\')) jQuery.post(ajaxurl, { action: \'coreylib_clear_cache\' }, function() { alert(\'Done!\'); });">Clear Cache</a>';
      return $actions;
    }
  }
}