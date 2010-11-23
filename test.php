<?php
/**
 * Run the coreylib tests.
 */
 
error_reporting(E_ERROR); 

// build and test, or test source?

if (isset($argv[1]) && $argv[1] == 'source') {
  require('src/coreylib.php');
} else {
  // build coreylib.php
  require('build.php');
  // load the library
  require('coreylib.php');
}

// run the tests
require('lib/simpletest/autorun.php');

class AllTests extends TestSuite {
  function AllTests() {
    parent::TestSuite();
    $dir = opendir(dirname(__FILE__).'/tests');
    while ($entry = readdir($dir)) {
      if ($entry != '.' && $entry != '..') {
        $this->addFile('tests/'.$entry);
      }
    }
    closedir($dir);
  }
}
