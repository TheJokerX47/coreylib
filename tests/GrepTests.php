<?php
class GrepTests extends UnitTestCase {
  
  function testGrep() {
    $apis = clApi::exec(array(
      'http://api.twitter.com/1/statuses/user_timeline.xml?screen_name=squidoo',
      'http://api.twitter.com/1/statuses/user_timeline.xml?screen_name=github',
    ));

    $statuses = clApi::grep($apis, 'status', 'date,desc:created_at');

    $dates = array_map( create_function('$s', '$s = json_decode($s->toJSON()); return $s->status->children->created_at->text;'), $statuses );
  }

}