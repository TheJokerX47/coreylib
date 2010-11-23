<?php
/**
 * Build coreylib.php from the files in src/
 */

// use the require() statements in src/coreylib.php to build the library.
$make = file_get_contents('src/coreylib.php');

preg_match_all('/require\(\'(.*)\'\);/', $make, $matches);

ob_start();

echo "<?php\n";

foreach($matches[1] as $file) {
  echo "// src/{$file}\n";
  echo preg_replace('/^<\?php/i', "\n", file_get_contents("src/{$file}"));
  echo "\n";
}

file_put_contents('coreylib.php', ob_get_clean());