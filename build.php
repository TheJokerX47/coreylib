<?php
/**
 * Build coreylib.php from the files in src/
 */

// use the require() statements in src/coreylib.php to build the library.
$make = file_get_contents('src/coreylib.php');

preg_match_all('/require\(\'(.*)\'\);/', $make, $matches);

ob_start();

echo "<?php\n";

echo "
/**
 * coreylib
 * Parse and cache XML and JSON.
 * @author Aaron Collegeman aaron@collegeman.net
 * @version 2.0
 *
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
  
";

foreach($matches[1] as $file) {
  echo "// src/{$file}\n";
  echo preg_replace('/^<\?php/i', "\n", file_get_contents("src/{$file}"));
  echo "\n";
}

file_put_contents('coreylib.php', ob_get_clean());