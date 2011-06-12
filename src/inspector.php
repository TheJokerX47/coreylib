<?php
if (COREYLIB_DEBUG) {
  ini_set('display_errors', false);
  
  trigger_error("COREYLIB_DEBUG is enabled", E_USER_WARNING);
  
  if ($url = @$_POST['url']) {
    if ($node = coreylib($url)) {
      header('Content-Type: application/json');
      if ($selector = @$_POST['selector']) {
        $node = $node->get($selector);
        if ($node->size() > 1) {
          $result = array();
          foreach($node as $n) {
            if (is_object($n)) {
              $result[] = (object) array_filter(array(
                'text' => trim($n->__toString()),
                'children' => $n->toArray(),
                'attribs' => $n->attribs()
              ));
            } else {
              $result[] = $n;
            }
          }
          echo json_encode($result);
        } else {
          echo $node->toJson();
        }
      } else {
        echo $node->toJson();
      }
    }
    exit;
    
  } else {
    ?>
      <script>!window.jQuery && document.write(unescape('%3Cscript src=\"//ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js\"%3E%3C/script%3E'))</script>
      <script>
        function coreylib(url, selector) {
          jQuery.ajax({
            url: 'coreylib.php', 
            data: { 'url': url, 'selector': selector },
            dataType: 'json',
            type: 'POST',
            success: function(json) {
              console.log(json.length, json);
            }
          });
          return "Downloading...";
        }
      </script>
    <?php
  }
}