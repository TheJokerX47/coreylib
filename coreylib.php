<?php
// src/oauth-support.php

 
/**
 * OAuth support classes.
 * @ref http://oauth.googlecode.com/svn/code/php/
 */
 
/* Generic exception class
 */
class OAuthException extends Exception {
  // pass
}

class OAuthConsumer {
  public $key;
  public $secret;

  function __construct($key, $secret, $callback_url=NULL) {
    $this->key = $key;
    $this->secret = $secret;
    $this->callback_url = $callback_url;
  }

  function __toString() {
    return "OAuthConsumer[key=$this->key,secret=$this->secret]";
  }
}

class OAuthToken {
  // access tokens and request tokens
  public $key;
  public $secret;

  /**
   * key = the token
   * secret = the token secret
   */
  function __construct($key, $secret) {
    $this->key = $key;
    $this->secret = $secret;
  }

  /**
   * generates the basic string serialization of a token that a server
   * would respond to request_token and access_token calls with
   */
  function to_string() {
    return "oauth_token=" .
           OAuthUtil::urlencode_rfc3986($this->key) .
           "&oauth_token_secret=" .
           OAuthUtil::urlencode_rfc3986($this->secret);
  }

  function __toString() {
    return $this->to_string();
  }
}

/**
 * A class for implementing a Signature Method
 * See section 9 ("Signing Requests") in the spec
 */
abstract class OAuthSignatureMethod {
  /**
   * Needs to return the name of the Signature Method (ie HMAC-SHA1)
   * @return string
   */
  abstract public function get_name();

  /**
   * Build up the signature
   * NOTE: The output of this function MUST NOT be urlencoded.
   * the encoding is handled in OAuthRequest when the final
   * request is serialized
   * @param OAuthRequest $request
   * @param OAuthConsumer $consumer
   * @param OAuthToken $token
   * @return string
   */
  abstract public function build_signature($request, $consumer, $token);

  /**
   * Verifies that a given signature is correct
   * @param OAuthRequest $request
   * @param OAuthConsumer $consumer
   * @param OAuthToken $token
   * @param string $signature
   * @return bool
   */
  public function check_signature($request, $consumer, $token, $signature) {
    $built = $this->build_signature($request, $consumer, $token);
    return $built == $signature;
  }
}

/**
 * The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104]
 * where the Signature Base String is the text and the key is the concatenated values (each first
 * encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&'
 * character (ASCII code 38) even if empty.
 *   - Chapter 9.2 ("HMAC-SHA1")
 */
class OAuthSignatureMethod_HMAC_SHA1 extends OAuthSignatureMethod {
  function get_name() {
    return "HMAC-SHA1";
  }

  public function build_signature($request, $consumer, $token) {
    $base_string = $request->get_signature_base_string();
    $request->base_string = $base_string;

    $key_parts = array(
      $consumer->secret,
      ($token) ? $token->secret : ""
    );

    $key_parts = OAuthUtil::urlencode_rfc3986($key_parts);
    $key = implode('&', $key_parts);

    return base64_encode(hash_hmac('sha1', $base_string, $key, true));
  }
}

/**
 * The PLAINTEXT method does not provide any security protection and SHOULD only be used
 * over a secure channel such as HTTPS. It does not use the Signature Base String.
 *   - Chapter 9.4 ("PLAINTEXT")
 */
class OAuthSignatureMethod_PLAINTEXT extends OAuthSignatureMethod {
  public function get_name() {
    return "PLAINTEXT";
  }

  /**
   * oauth_signature is set to the concatenated encoded values of the Consumer Secret and
   * Token Secret, separated by a '&' character (ASCII code 38), even if either secret is
   * empty. The result MUST be encoded again.
   *   - Chapter 9.4.1 ("Generating Signatures")
   *
   * Please note that the second encoding MUST NOT happen in the SignatureMethod, as
   * OAuthRequest handles this!
   */
  public function build_signature($request, $consumer, $token) {
    $key_parts = array(
      $consumer->secret,
      ($token) ? $token->secret : ""
    );

    $key_parts = OAuthUtil::urlencode_rfc3986($key_parts);
    $key = implode('&', $key_parts);
    $request->base_string = $key;

    return $key;
  }
}

/**
 * The RSA-SHA1 signature method uses the RSASSA-PKCS1-v1_5 signature algorithm as defined in
 * [RFC3447] section 8.2 (more simply known as PKCS#1), using SHA-1 as the hash function for
 * EMSA-PKCS1-v1_5. It is assumed that the Consumer has provided its RSA public key in a
 * verified way to the Service Provider, in a manner which is beyond the scope of this
 * specification.
 *   - Chapter 9.3 ("RSA-SHA1")
 */
abstract class OAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod {
  public function get_name() {
    return "RSA-SHA1";
  }

  // Up to the SP to implement this lookup of keys. Possible ideas are:
  // (1) do a lookup in a table of trusted certs keyed off of consumer
  // (2) fetch via http using a url provided by the requester
  // (3) some sort of specific discovery code based on request
  //
  // Either way should return a string representation of the certificate
  protected abstract function fetch_public_cert(&$request);

  // Up to the SP to implement this lookup of keys. Possible ideas are:
  // (1) do a lookup in a table of trusted certs keyed off of consumer
  //
  // Either way should return a string representation of the certificate
  protected abstract function fetch_private_cert(&$request);

  public function build_signature($request, $consumer, $token) {
    $base_string = $request->get_signature_base_string();
    $request->base_string = $base_string;

    // Fetch the private key cert based on the request
    $cert = $this->fetch_private_cert($request);

    // Pull the private key ID from the certificate
    $privatekeyid = openssl_get_privatekey($cert);

    // Sign using the key
    $ok = openssl_sign($base_string, $signature, $privatekeyid);

    // Release the key resource
    openssl_free_key($privatekeyid);

    return base64_encode($signature);
  }

  public function check_signature($request, $consumer, $token, $signature) {
    $decoded_sig = base64_decode($signature);

    $base_string = $request->get_signature_base_string();

    // Fetch the public key cert based on the request
    $cert = $this->fetch_public_cert($request);

    // Pull the public key ID from the certificate
    $publickeyid = openssl_get_publickey($cert);

    // Check the computed signature against the one passed in the query
    $ok = openssl_verify($base_string, $decoded_sig, $publickeyid);

    // Release the key resource
    openssl_free_key($publickeyid);

    return $ok == 1;
  }
}

class OAuthRequest {
  protected $parameters;
  protected $http_method;
  protected $http_url;
  // for debug purposes
  public $base_string;
  public static $version = '1.0';
  public static $POST_INPUT = 'php://input';

  function __construct($http_method, $http_url, $parameters=NULL) {
    $parameters = ($parameters) ? $parameters : array();
    $parameters = array_merge( OAuthUtil::parse_parameters(parse_url($http_url, PHP_URL_QUERY)), $parameters);
    $this->parameters = $parameters;
    $this->http_method = $http_method;
    $this->http_url = $http_url;
  }


  /**
   * attempt to build up a request from what was passed to the server
   */
  public static function from_request($http_method=NULL, $http_url=NULL, $parameters=NULL) {
    $scheme = (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != "on")
              ? 'http'
              : 'https';
    $http_url = ($http_url) ? $http_url : $scheme .
                              '://' . $_SERVER['HTTP_HOST'] .
                              ':' .
                              $_SERVER['SERVER_PORT'] .
                              $_SERVER['REQUEST_URI'];
    $http_method = ($http_method) ? $http_method : $_SERVER['REQUEST_METHOD'];

    // We weren't handed any parameters, so let's find the ones relevant to
    // this request.
    // If you run XML-RPC or similar you should use this to provide your own
    // parsed parameter-list
    if (!$parameters) {
      // Find request headers
      $request_headers = OAuthUtil::get_headers();

      // Parse the query-string to find GET parameters
      $parameters = OAuthUtil::parse_parameters($_SERVER['QUERY_STRING']);

      // It's a POST request of the proper content-type, so parse POST
      // parameters and add those overriding any duplicates from GET
      if ($http_method == "POST"
          &&  isset($request_headers['Content-Type'])
          && strstr($request_headers['Content-Type'],
                     'application/x-www-form-urlencoded')
          ) {
        $post_data = OAuthUtil::parse_parameters(
          file_get_contents(self::$POST_INPUT)
        );
        $parameters = array_merge($parameters, $post_data);
      }

      // We have a Authorization-header with OAuth data. Parse the header
      // and add those overriding any duplicates from GET or POST
      if (isset($request_headers['Authorization']) && substr($request_headers['Authorization'], 0, 6) == 'OAuth ') {
        $header_parameters = OAuthUtil::split_header(
          $request_headers['Authorization']
        );
        $parameters = array_merge($parameters, $header_parameters);
      }

    }

    return new OAuthRequest($http_method, $http_url, $parameters);
  }

  /**
   * pretty much a helper function to set up the request
   */
  public static function from_consumer_and_token($consumer, $token, $http_method, $http_url, $parameters=NULL) {
    $parameters = ($parameters) ?  $parameters : array();
    $defaults = array("oauth_version" => OAuthRequest::$version,
                      "oauth_nonce" => OAuthRequest::generate_nonce(),
                      "oauth_timestamp" => OAuthRequest::generate_timestamp(),
                      "oauth_consumer_key" => $consumer->key);
    if ($token)
      $defaults['oauth_token'] = $token->key;

    $parameters = array_merge($defaults, $parameters);

    return new OAuthRequest($http_method, $http_url, $parameters);
  }

  public function set_parameter($name, $value, $allow_duplicates = true) {
    if ($allow_duplicates && isset($this->parameters[$name])) {
      // We have already added parameter(s) with this name, so add to the list
      if (is_scalar($this->parameters[$name])) {
        // This is the first duplicate, so transform scalar (string)
        // into an array so we can add the duplicates
        $this->parameters[$name] = array($this->parameters[$name]);
      }

      $this->parameters[$name][] = $value;
    } else {
      $this->parameters[$name] = $value;
    }
  }

  public function get_parameter($name) {
    return isset($this->parameters[$name]) ? $this->parameters[$name] : null;
  }

  public function get_parameters() {
    return $this->parameters;
  }

  public function unset_parameter($name) {
    unset($this->parameters[$name]);
  }

  /**
   * The request parameters, sorted and concatenated into a normalized string.
   * @return string
   */
  public function get_signable_parameters() {
    // Grab all parameters
    $params = $this->parameters;

    // Remove oauth_signature if present
    // Ref: Spec: 9.1.1 ("The oauth_signature parameter MUST be excluded.")
    if (isset($params['oauth_signature'])) {
      unset($params['oauth_signature']);
    }

    return OAuthUtil::build_http_query($params);
  }

  /**
   * Returns the base string of this request
   *
   * The base string defined as the method, the url
   * and the parameters (normalized), each urlencoded
   * and the concated with &.
   */
  public function get_signature_base_string() {
    $parts = array(
      $this->get_normalized_http_method(),
      $this->get_normalized_http_url(),
      $this->get_signable_parameters()
    );

    $parts = OAuthUtil::urlencode_rfc3986($parts);

    return implode('&', $parts);
  }

  /**
   * just uppercases the http method
   */
  public function get_normalized_http_method() {
    return strtoupper($this->http_method);
  }

  /**
   * parses the url and rebuilds it to be
   * scheme://host/path
   */
  public function get_normalized_http_url() {
    $parts = parse_url($this->http_url);

    $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
    $port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
    $host = (isset($parts['host'])) ? $parts['host'] : '';
    $path = (isset($parts['path'])) ? $parts['path'] : '';

    if (($scheme == 'https' && $port != '443')
        || ($scheme == 'http' && $port != '80')) {
      $host = "$host:$port";
    }
    return "$scheme://$host$path";
  }

  /**
   * builds a url usable for a GET request
   */
  public function to_url() {
    $post_data = $this->to_postdata();
    $out = $this->get_normalized_http_url();
    if ($post_data) {
      $out .= '?'.$post_data;
    }
    return $out;
  }

  /**
   * builds the data one would send in a POST request
   */
  public function to_postdata() {
    return OAuthUtil::build_http_query($this->parameters);
  }

  /**
   * builds the Authorization: header
   */
  public function to_header($realm=null) {
    $first = true;
	if($realm) {
      $out = 'Authorization: OAuth realm="' . OAuthUtil::urlencode_rfc3986($realm) . '"';
      $first = false;
    } else
      $out = 'Authorization: OAuth';

    $total = array();
    foreach ($this->parameters as $k => $v) {
      if (substr($k, 0, 5) != "oauth") continue;
      if (is_array($v)) {
        throw new OAuthException('Arrays not supported in headers');
      }
      $out .= ($first) ? ' ' : ',';
      $out .= OAuthUtil::urlencode_rfc3986($k) .
              '="' .
              OAuthUtil::urlencode_rfc3986($v) .
              '"';
      $first = false;
    }
    return $out;
  }

  public function __toString() {
    return $this->to_url();
  }


  public function sign_request($signature_method, $consumer, $token) {
    $this->set_parameter(
      "oauth_signature_method",
      $signature_method->get_name(),
      false
    );
    $signature = $this->build_signature($signature_method, $consumer, $token);
    $this->set_parameter("oauth_signature", $signature, false);
  }

  public function build_signature($signature_method, $consumer, $token) {
    $signature = $signature_method->build_signature($this, $consumer, $token);
    return $signature;
  }

  /**
   * util function: current timestamp
   */
  private static function generate_timestamp() {
    return time();
  }

  /**
   * util function: current nonce
   */
  public static function generate_nonce() {
    $mt = microtime();
    $rand = mt_rand();

    return md5($mt . $rand); // md5s look nicer than numbers
  }
}

class OAuthServer {
  protected $timestamp_threshold = 300; // in seconds, five minutes
  protected $version = '1.0';             // hi blaine
  protected $signature_methods = array();

  protected $data_store;

  function __construct($data_store) {
    $this->data_store = $data_store;
  }

  public function add_signature_method($signature_method) {
    $this->signature_methods[$signature_method->get_name()] =
      $signature_method;
  }

  // high level functions

  /**
   * process a request_token request
   * returns the request token on success
   */
  public function fetch_request_token(&$request) {
    $this->get_version($request);

    $consumer = $this->get_consumer($request);

    // no token required for the initial token request
    $token = NULL;

    $this->check_signature($request, $consumer, $token);

    // Rev A change
    $callback = $request->get_parameter('oauth_callback');
    $new_token = $this->data_store->new_request_token($consumer, $callback);

    return $new_token;
  }

  /**
   * process an access_token request
   * returns the access token on success
   */
  public function fetch_access_token(&$request) {
    $this->get_version($request);

    $consumer = $this->get_consumer($request);

    // requires authorized request token
    $token = $this->get_token($request, $consumer, "request");

    $this->check_signature($request, $consumer, $token);

    // Rev A change
    $verifier = $request->get_parameter('oauth_verifier');
    $new_token = $this->data_store->new_access_token($token, $consumer, $verifier);

    return $new_token;
  }

  /**
   * verify an api call, checks all the parameters
   */
  public function verify_request(&$request) {
    $this->get_version($request);
    $consumer = $this->get_consumer($request);
    $token = $this->get_token($request, $consumer, "access");
    $this->check_signature($request, $consumer, $token);
    return array($consumer, $token);
  }

  // Internals from here
  /**
   * version 1
   */
  private function get_version(&$request) {
    $version = $request->get_parameter("oauth_version");
    if (!$version) {
      // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
      // Chapter 7.0 ("Accessing Protected Ressources")
      $version = '1.0';
    }
    if ($version !== $this->version) {
      throw new OAuthException("OAuth version '$version' not supported");
    }
    return $version;
  }

  /**
   * figure out the signature with some defaults
   */
  private function get_signature_method($request) {
    $signature_method = $request instanceof OAuthRequest
        ? $request->get_parameter("oauth_signature_method")
        : NULL;

    if (!$signature_method) {
      // According to chapter 7 ("Accessing Protected Ressources") the signature-method
      // parameter is required, and we can't just fallback to PLAINTEXT
      throw new OAuthException('No signature method parameter. This parameter is required');
    }

    if (!in_array($signature_method,
                  array_keys($this->signature_methods))) {
      throw new OAuthException(
        "Signature method '$signature_method' not supported " .
        "try one of the following: " .
        implode(", ", array_keys($this->signature_methods))
      );
    }
    return $this->signature_methods[$signature_method];
  }

  /**
   * try to find the consumer for the provided request's consumer key
   */
  private function get_consumer($request) {
    $consumer_key = $request instanceof OAuthRequest
        ? $request->get_parameter("oauth_consumer_key")
        : NULL;

    if (!$consumer_key) {
      throw new OAuthException("Invalid consumer key");
    }

    $consumer = $this->data_store->lookup_consumer($consumer_key);
    if (!$consumer) {
      throw new OAuthException("Invalid consumer");
    }

    return $consumer;
  }

  /**
   * try to find the token for the provided request's token key
   */
  private function get_token($request, $consumer, $token_type="access") {
    $token_field = $request instanceof OAuthRequest
         ? $request->get_parameter('oauth_token')
         : NULL;

    $token = $this->data_store->lookup_token(
      $consumer, $token_type, $token_field
    );
    if (!$token) {
      throw new OAuthException("Invalid $token_type token: $token_field");
    }
    return $token;
  }

  /**
   * all-in-one function to check the signature on a request
   * should guess the signature method appropriately
   */
  private function check_signature($request, $consumer, $token) {
    // this should probably be in a different method
    $timestamp = $request instanceof OAuthRequest
        ? $request->get_parameter('oauth_timestamp')
        : NULL;
    $nonce = $request instanceof OAuthRequest
        ? $request->get_parameter('oauth_nonce')
        : NULL;

    $this->check_timestamp($timestamp);
    $this->check_nonce($consumer, $token, $nonce, $timestamp);

    $signature_method = $this->get_signature_method($request);

    $signature = $request->get_parameter('oauth_signature');
    $valid_sig = $signature_method->check_signature(
      $request,
      $consumer,
      $token,
      $signature
    );

    if (!$valid_sig) {
      throw new OAuthException("Invalid signature");
    }
  }

  /**
   * check that the timestamp is new enough
   */
  private function check_timestamp($timestamp) {
    if( ! $timestamp )
      throw new OAuthException(
        'Missing timestamp parameter. The parameter is required'
      );

    // verify that timestamp is recentish
    $now = time();
    if (abs($now - $timestamp) > $this->timestamp_threshold) {
      throw new OAuthException(
        "Expired timestamp, yours $timestamp, ours $now"
      );
    }
  }

  /**
   * check that the nonce is not repeated
   */
  private function check_nonce($consumer, $token, $nonce, $timestamp) {
    if( ! $nonce )
      throw new OAuthException(
        'Missing nonce parameter. The parameter is required'
      );

    // verify that the nonce is uniqueish
    $found = $this->data_store->lookup_nonce(
      $consumer,
      $token,
      $nonce,
      $timestamp
    );
    if ($found) {
      throw new OAuthException("Nonce already used: $nonce");
    }
  }

}

class OAuthDataStore {
  function lookup_consumer($consumer_key) {
    // implement me
  }

  function lookup_token($consumer, $token_type, $token) {
    // implement me
  }

  function lookup_nonce($consumer, $token, $nonce, $timestamp) {
    // implement me
  }

  function new_request_token($consumer, $callback = null) {
    // return a new token attached to this consumer
  }

  function new_access_token($token, $consumer, $verifier = null) {
    // return a new access token attached to this consumer
    // for the user associated with this token if the request token
    // is authorized
    // should also invalidate the request token
  }

}

class OAuthUtil {
  public static function urlencode_rfc3986($input) {
  if (is_array($input)) {
    return array_map(array('OAuthUtil', 'urlencode_rfc3986'), $input);
  } else if (is_scalar($input)) {
    return str_replace(
      '+',
      ' ',
      str_replace('%7E', '~', rawurlencode($input))
    );
  } else {
    return '';
  }
}


  // This decode function isn't taking into consideration the above
  // modifications to the encoding process. However, this method doesn't
  // seem to be used anywhere so leaving it as is.
  public static function urldecode_rfc3986($string) {
    return urldecode($string);
  }

  // Utility function for turning the Authorization: header into
  // parameters, has to do some unescaping
  // Can filter out any non-oauth parameters if needed (default behaviour)
  // May 28th, 2010 - method updated to tjerk.meesters for a speed improvement.
  //                  see http://code.google.com/p/oauth/issues/detail?id=163
  public static function split_header($header, $only_allow_oauth_parameters = true) {
    $params = array();
    if (preg_match_all('/('.($only_allow_oauth_parameters ? 'oauth_' : '').'[a-z_-]*)=(:?"([^"]*)"|([^,]*))/', $header, $matches)) {
      foreach ($matches[1] as $i => $h) {
        $params[$h] = OAuthUtil::urldecode_rfc3986(empty($matches[3][$i]) ? $matches[4][$i] : $matches[3][$i]);
      }
      if (isset($params['realm'])) {
        unset($params['realm']);
      }
    }
    return $params;
  }

  // helper to try to sort out headers for people who aren't running apache
  public static function get_headers() {
    if (function_exists('apache_request_headers')) {
      // we need this to get the actual Authorization: header
      // because apache tends to tell us it doesn't exist
      $headers = apache_request_headers();

      // sanitize the output of apache_request_headers because
      // we always want the keys to be Cased-Like-This and arh()
      // returns the headers in the same case as they are in the
      // request
      $out = array();
      foreach ($headers AS $key => $value) {
        $key = str_replace(
            " ",
            "-",
            ucwords(strtolower(str_replace("-", " ", $key)))
          );
        $out[$key] = $value;
      }
    } else {
      // otherwise we don't have apache and are just going to have to hope
      // that $_SERVER actually contains what we need
      $out = array();
      if( isset($_SERVER['CONTENT_TYPE']) )
        $out['Content-Type'] = $_SERVER['CONTENT_TYPE'];
      if( isset($_ENV['CONTENT_TYPE']) )
        $out['Content-Type'] = $_ENV['CONTENT_TYPE'];

      foreach ($_SERVER as $key => $value) {
        if (substr($key, 0, 5) == "HTTP_") {
          // this is chaos, basically it is just there to capitalize the first
          // letter of every word that is not an initial HTTP and strip HTTP
          // code from przemek
          $key = str_replace(
            " ",
            "-",
            ucwords(strtolower(str_replace("_", " ", substr($key, 5))))
          );
          $out[$key] = $value;
        }
      }
    }
    return $out;
  }

  // This function takes a input like a=b&a=c&d=e and returns the parsed
  // parameters like this
  // array('a' => array('b','c'), 'd' => 'e')
  public static function parse_parameters( $input ) {
    if (!isset($input) || !$input) return array();

    $pairs = explode('&', $input);

    $parsed_parameters = array();
    foreach ($pairs as $pair) {
      $split = explode('=', $pair, 2);
      $parameter = OAuthUtil::urldecode_rfc3986($split[0]);
      $value = isset($split[1]) ? OAuthUtil::urldecode_rfc3986($split[1]) : '';

      if (isset($parsed_parameters[$parameter])) {
        // We have already recieved parameter(s) with this name, so add to the list
        // of parameters with this name

        if (is_scalar($parsed_parameters[$parameter])) {
          // This is the first duplicate, so transform scalar (string) into an array
          // so we can add the duplicates
          $parsed_parameters[$parameter] = array($parsed_parameters[$parameter]);
        }

        $parsed_parameters[$parameter][] = $value;
      } else {
        $parsed_parameters[$parameter] = $value;
      }
    }
    return $parsed_parameters;
  }

  public static function build_http_query($params) {
    if (!$params) return '';

    // Urlencode both keys and values
    $keys = OAuthUtil::urlencode_rfc3986(array_keys($params));
    $values = OAuthUtil::urlencode_rfc3986(array_values($params));
    $params = array_combine($keys, $values);

    // Parameters are sorted by name, using lexicographical byte value ordering.
    // Ref: Spec: 9.1.1 (1)
    uksort($params, 'strcmp');

    $pairs = array();
    foreach ($params as $parameter => $value) {
      if (is_array($value)) {
        // If two or more parameters share the same name, they are sorted by their value
        // Ref: Spec: 9.1.1 (1)
        // June 12th, 2010 - changed to sort because of issue 164 by hidetaka
        sort($value, SORT_STRING);
        foreach ($value as $duplicate_value) {
          $pairs[] = $parameter . '=' . $duplicate_value;
        }
      } else {
        $pairs[] = $parameter . '=' . $value;
      }
    }
    // For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
    // Each name-value pair is separated by an '&' character (ASCII code 38)
    return implode('&', $pairs);
  }
}
// src/facebook-sdk-2.1.2.php


if (!class_exists('Facebook')):

if (!function_exists('curl_init')) {
  throw new Exception('Facebook needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
  throw new Exception('Facebook needs the JSON PHP extension.');
}

/**
 * Thrown when an API call returns an exception.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
class FacebookApiException extends Exception
{
  /**
   * The result from the API server that represents the exception information.
   */
  protected $result;

  /**
   * Make a new API Exception with the given result.
   *
   * @param Array $result the result from the API server
   */
  public function __construct($result) {
    $this->result = $result;

    $code = isset($result['error_code']) ? $result['error_code'] : 0;
    $msg  = isset($result['error'])
              ? $result['error']['message'] : $result['error_msg'];
    parent::__construct($msg, $code);
  }

  /**
   * Return the associated result object returned by the API server.
   *
   * @returns Array the result from the API server
   */
  public function getResult() {
    return $this->result;
  }

  /**
   * Returns the associated type for the error. This will default to
   * 'Exception' when a type is not available.
   *
   * @return String
   */
  public function getType() {
    return
      isset($this->result['error']) && isset($this->result['error']['type'])
      ? $this->result['error']['type']
      : 'Exception';
  }

  /**
   * To make debugging easier.
   *
   * @returns String the string representation of the error
   */
  public function __toString() {
    $str = $this->getType() . ': ';
    if ($this->code != 0) {
      $str .= $this->code . ': ';
    }
    return $str . $this->message;
  }
}

/**
 * Provides access to the Facebook Platform.
 *
 * @author Naitik Shah <naitik@facebook.com>
 */
class Facebook
{
  /**
   * Version.
   */
  const VERSION = '2.1.1';

  /**
   * Default options for curl.
   */
  public static $CURL_OPTS = array(
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 60,
    CURLOPT_USERAGENT      => 'facebook-php-2.0',
  );

  /**
   * List of query parameters that get automatically dropped when rebuilding
   * the current URL.
   */
  protected static $DROP_QUERY_PARAMS = array(
    'session',
    'signed_request',
  );

  /**
   * Maps aliases to Facebook domains.
   */
  public static $DOMAIN_MAP = array(
    'api'      => 'https://api.facebook.com/',
    'api_read' => 'https://api-read.facebook.com/',
    'graph'    => 'https://graph.facebook.com/',
    'www'      => 'https://www.facebook.com/',
  );

  /**
   * The Application ID.
   */
  protected $appId;

  /**
   * The Application API Secret.
   */
  protected $apiSecret;

  /**
   * The active user session, if one is available.
   */
  protected $session;

  /**
   * The data from the signed_request token.
   */
  protected $signedRequest;

  /**
   * Indicates that we already loaded the session as best as we could.
   */
  protected $sessionLoaded = false;

  /**
   * Indicates if Cookie support should be enabled.
   */
  protected $cookieSupport = false;

  /**
   * Base domain for the Cookie.
   */
  protected $baseDomain = '';

  /**
   * Indicates if the CURL based @ syntax for file uploads is enabled.
   */
  protected $fileUploadSupport = false;

  /**
   * Initialize a Facebook Application.
   *
   * The configuration:
   * - appId: the application ID
   * - secret: the application secret
   * - cookie: (optional) boolean true to enable cookie support
   * - domain: (optional) domain for the cookie
   * - fileUpload: (optional) boolean indicating if file uploads are enabled
   *
   * @param Array $config the application configuration
   */
  public function __construct($config) {
    $this->setAppId($config['appId']);
    $this->setApiSecret($config['secret']);
    if (isset($config['cookie'])) {
      $this->setCookieSupport($config['cookie']);
    }
    if (isset($config['domain'])) {
      $this->setBaseDomain($config['domain']);
    }
    if (isset($config['fileUpload'])) {
      $this->setFileUploadSupport($config['fileUpload']);
    }
  }

  /**
   * Set the Application ID.
   *
   * @param String $appId the Application ID
   */
  public function setAppId($appId) {
    $this->appId = $appId;
    return $this;
  }

  /**
   * Get the Application ID.
   *
   * @return String the Application ID
   */
  public function getAppId() {
    return $this->appId;
  }

  /**
   * Set the API Secret.
   *
   * @param String $appId the API Secret
   */
  public function setApiSecret($apiSecret) {
    $this->apiSecret = $apiSecret;
    return $this;
  }

  /**
   * Get the API Secret.
   *
   * @return String the API Secret
   */
  public function getApiSecret() {
    return $this->apiSecret;
  }

  /**
   * Set the Cookie Support status.
   *
   * @param Boolean $cookieSupport the Cookie Support status
   */
  public function setCookieSupport($cookieSupport) {
    $this->cookieSupport = $cookieSupport;
    return $this;
  }

  /**
   * Get the Cookie Support status.
   *
   * @return Boolean the Cookie Support status
   */
  public function useCookieSupport() {
    return $this->cookieSupport;
  }

  /**
   * Set the base domain for the Cookie.
   *
   * @param String $domain the base domain
   */
  public function setBaseDomain($domain) {
    $this->baseDomain = $domain;
    return $this;
  }

  /**
   * Get the base domain for the Cookie.
   *
   * @return String the base domain
   */
  public function getBaseDomain() {
    return $this->baseDomain;
  }

  /**
   * Set the file upload support status.
   *
   * @param String $domain the base domain
   */
  public function setFileUploadSupport($fileUploadSupport) {
    $this->fileUploadSupport = $fileUploadSupport;
    return $this;
  }

  /**
   * Get the file upload support status.
   *
   * @return String the base domain
   */
  public function useFileUploadSupport() {
    return $this->fileUploadSupport;
  }

  /**
   * Get the data from a signed_request token
   *
   * @return String the base domain
   */
  public function getSignedRequest() {
    if (!$this->signedRequest) {
      if (isset($_REQUEST['signed_request'])) {
        $this->signedRequest = $this->parseSignedRequest(
          $_REQUEST['signed_request']);
      }
    }
    return $this->signedRequest;
  }

  /**
   * Set the Session.
   *
   * @param Array $session the session
   * @param Boolean $write_cookie indicate if a cookie should be written. this
   * value is ignored if cookie support has been disabled.
   */
  public function setSession($session=null, $write_cookie=true) {
    $session = $this->validateSessionObject($session);
    $this->sessionLoaded = true;
    $this->session = $session;
    if ($write_cookie) {
      $this->setCookieFromSession($session);
    }
    return $this;
  }

  /**
   * Get the session object. This will automatically look for a signed session
   * sent via the signed_request, Cookie or Query Parameters if needed.
   *
   * @return Array the session
   */
  public function getSession() {
    if (!$this->sessionLoaded) {
      $session = null;
      $write_cookie = true;

      // try loading session from signed_request in $_REQUEST
      $signedRequest = $this->getSignedRequest();
      if ($signedRequest) {
        // sig is good, use the signedRequest
        $session = $this->createSessionFromSignedRequest($signedRequest);
      }

      // try loading session from $_REQUEST
      if (!$session && isset($_REQUEST['session'])) {
        $session = json_decode(
          get_magic_quotes_gpc()
            ? stripslashes($_REQUEST['session'])
            : $_REQUEST['session'],
          true
        );
        $session = $this->validateSessionObject($session);
      }

      // try loading session from cookie if necessary
      if (!$session && $this->useCookieSupport()) {
        $cookieName = $this->getSessionCookieName();
        if (isset($_COOKIE[$cookieName])) {
          $session = array();
          parse_str(trim(
            get_magic_quotes_gpc()
              ? stripslashes($_COOKIE[$cookieName])
              : $_COOKIE[$cookieName],
            '"'
          ), $session);
          $session = $this->validateSessionObject($session);
          // write only if we need to delete a invalid session cookie
          $write_cookie = empty($session);
        }
      }

      $this->setSession($session, $write_cookie);
    }

    return $this->session;
  }

  /**
   * Get the UID from the session.
   *
   * @return String the UID if available
   */
  public function getUser() {
    $session = $this->getSession();
    return $session ? $session['uid'] : null;
  }

  /**
   * Gets a OAuth access token.
   *
   * @return String the access token
   */
  public function getAccessToken() {
    $session = $this->getSession();
    // either user session signed, or app signed
    if ($session) {
      return $session['access_token'];
    } else {
      return $this->getAppId() .'|'. $this->getApiSecret();
    }
  }

  /**
   * Get a Login URL for use with redirects. By default, full page redirect is
   * assumed. If you are using the generated URL with a window.open() call in
   * JavaScript, you can pass in display=popup as part of the $params.
   *
   * The parameters:
   * - next: the url to go to after a successful login
   * - cancel_url: the url to go to after the user cancels
   * - req_perms: comma separated list of requested extended perms
   * - display: can be "page" (default, full page) or "popup"
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the login flow
   */
  public function getLoginUrl($params=array()) {
    $currentUrl = $this->getCurrentUrl();
    return $this->getUrl(
      'www',
      'login.php',
      array_merge(array(
        'api_key'         => $this->getAppId(),
        'cancel_url'      => $currentUrl,
        'display'         => 'page',
        'fbconnect'       => 1,
        'next'            => $currentUrl,
        'return_session'  => 1,
        'session_version' => 3,
        'v'               => '1.0',
      ), $params)
    );
  }

  /**
   * Get a Logout URL suitable for use with redirects.
   *
   * The parameters:
   * - next: the url to go to after a successful logout
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the logout flow
   */
  public function getLogoutUrl($params=array()) {
    return $this->getUrl(
      'www',
      'logout.php',
      array_merge(array(
        'next'         => $this->getCurrentUrl(),
        'access_token' => $this->getAccessToken(),
      ), $params)
    );
  }

  /**
   * Get a login status URL to fetch the status from facebook.
   *
   * The parameters:
   * - ok_session: the URL to go to if a session is found
   * - no_session: the URL to go to if the user is not connected
   * - no_user: the URL to go to if the user is not signed into facebook
   *
   * @param Array $params provide custom parameters
   * @return String the URL for the logout flow
   */
  public function getLoginStatusUrl($params=array()) {
    return $this->getUrl(
      'www',
      'extern/login_status.php',
      array_merge(array(
        'api_key'         => $this->getAppId(),
        'no_session'      => $this->getCurrentUrl(),
        'no_user'         => $this->getCurrentUrl(),
        'ok_session'      => $this->getCurrentUrl(),
        'session_version' => 3,
      ), $params)
    );
  }

  /**
   * Make an API call.
   *
   * @param Array $params the API call parameters
   * @return the decoded response
   */
  public function api(/* polymorphic */) {
    $args = func_get_args();
    if (is_array($args[0])) {
      return $this->_restserver($args[0]);
    } else {
      return call_user_func_array(array($this, '_graph'), $args);
    }
  }

  /**
   * Invoke the old restserver.php endpoint.
   *
   * @param Array $params method call object
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _restserver($params) {
    // generic application level parameters
    $params['api_key'] = $this->getAppId();
    $params['format'] = 'json-strings';

    $result = json_decode($this->_oauthRequest(
      $this->getApiUrl($params['method']),
      $params
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error_code'])) {
      throw new FacebookApiException($result);
    }
    return $result;
  }

  /**
   * Invoke the Graph API.
   *
   * @param String $path the path (required)
   * @param String $method the http method (default 'GET')
   * @param Array $params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _graph($path, $method='GET', $params=array()) {
    if (is_array($method) && empty($params)) {
      $params = $method;
      $method = 'GET';
    }
    $params['method'] = $method; // method override as we always do a POST

    $result = json_decode($this->_oauthRequest(
      $this->getUrl('graph', $path),
      $params
    ), true);

    // results are returned, errors are thrown
    if (is_array($result) && isset($result['error'])) {
      $e = new FacebookApiException($result);
      if ($e->getType() === 'OAuthException') {
        $this->setSession(null);
      }
      throw $e;
    }
    return $result;
  }

  /**
   * Make a OAuth Request
   *
   * @param String $path the path (required)
   * @param Array $params the query/post data
   * @return the decoded response object
   * @throws FacebookApiException
   */
  protected function _oauthRequest($url, $params) {
    if (!isset($params['access_token'])) {
      $params['access_token'] = $this->getAccessToken();
    }

    // json_encode all params values that are not strings
    foreach ($params as $key => $value) {
      if (!is_string($value)) {
        $params[$key] = json_encode($value);
      }
    }
    return $this->makeRequest($url, $params);
  }

  /**
   * Makes an HTTP request. This method can be overriden by subclasses if
   * developers want to do fancier things or use something other than curl to
   * make the request.
   *
   * @param String $url the URL to make the request to
   * @param Array $params the parameters to use for the POST body
   * @param CurlHandler $ch optional initialized curl handle
   * @return String the response text
   */
  protected function makeRequest($url, $params, $ch=null) {
    if (!$ch) {
      $ch = curl_init();
    }

    $opts = self::$CURL_OPTS;
    if ($this->useFileUploadSupport()) {
      $opts[CURLOPT_POSTFIELDS] = $params;
    } else {
      $opts[CURLOPT_POSTFIELDS] = http_build_query($params, null, '&');
    }
    $opts[CURLOPT_URL] = $url;

    // disable the 'Expect: 100-continue' behaviour. This causes CURL to wait
    // for 2 seconds if the server does not support this header.
    if (isset($opts[CURLOPT_HTTPHEADER])) {
      $existing_headers = $opts[CURLOPT_HTTPHEADER];
      $existing_headers[] = 'Expect:';
      $opts[CURLOPT_HTTPHEADER] = $existing_headers;
    } else {
      $opts[CURLOPT_HTTPHEADER] = array('Expect:');
    }

    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    if ($result === false) {
      $e = new FacebookApiException(array(
        'error_code' => curl_errno($ch),
        'error'      => array(
          'message' => curl_error($ch),
          'type'    => 'CurlException',
        ),
      ));
      curl_close($ch);
      throw $e;
    }
    curl_close($ch);
    return $result;
  }

  /**
   * The name of the Cookie that contains the session.
   *
   * @return String the cookie name
   */
  protected function getSessionCookieName() {
    return 'fbs_' . $this->getAppId();
  }

  /**
   * Set a JS Cookie based on the _passed in_ session. It does not use the
   * currently stored session -- you need to explicitly pass it in.
   *
   * @param Array $session the session to use for setting the cookie
   */
  protected function setCookieFromSession($session=null) {
    if (!$this->useCookieSupport()) {
      return;
    }

    $cookieName = $this->getSessionCookieName();
    $value = 'deleted';
    $expires = time() - 3600;
    $domain = $this->getBaseDomain();
    if ($session) {
      $value = '"' . http_build_query($session, null, '&') . '"';
      if (isset($session['base_domain'])) {
        $domain = $session['base_domain'];
      }
      $expires = $session['expires'];
    }

    // prepend dot if a domain is found
    if ($domain) {
      $domain = '.' . $domain;
    }

    // if an existing cookie is not set, we dont need to delete it
    if ($value == 'deleted' && empty($_COOKIE[$cookieName])) {
      return;
    }

    if (headers_sent()) {
      self::errorLog('Could not set cookie. Headers already sent.');

    // ignore for code coverage as we will never be able to setcookie in a CLI
    // environment
    // @codeCoverageIgnoreStart
    } else {
      setcookie($cookieName, $value, $expires, '/', $domain);
    }
    // @codeCoverageIgnoreEnd
  }

  /**
   * Validates a session_version=3 style session object.
   *
   * @param Array $session the session object
   * @return Array the session object if it validates, null otherwise
   */
  protected function validateSessionObject($session) {
    // make sure some essential fields exist
    if (is_array($session) &&
        isset($session['uid']) &&
        isset($session['access_token']) &&
        isset($session['sig'])) {
      // validate the signature
      $session_without_sig = $session;
      unset($session_without_sig['sig']);
      $expected_sig = self::generateSignature(
        $session_without_sig,
        $this->getApiSecret()
      );
      if ($session['sig'] != $expected_sig) {
        self::errorLog('Got invalid session signature in cookie.');
        $session = null;
      }
      // check expiry time
    } else {
      $session = null;
    }
    return $session;
  }

  /**
   * Returns something that looks like our JS session object from the
   * signed token's data
   *
   * TODO: Nuke this once the login flow uses OAuth2
   *
   * @param Array the output of getSignedRequest
   * @return Array Something that will work as a session
   */
  protected function createSessionFromSignedRequest($data) {
    if (!isset($data['oauth_token'])) {
      return null;
    }

    $session = array(
      'uid'          => $data['user_id'],
      'access_token' => $data['oauth_token'],
      'expires'      => $data['expires'],
    );

    // put a real sig, so that validateSignature works
    $session['sig'] = self::generateSignature(
      $session,
      $this->getApiSecret()
    );

    return $session;
  }

  /**
   * Parses a signed_request and validates the signature.
   * Then saves it in $this->signed_data
   *
   * @param String A signed token
   * @param Boolean Should we remove the parts of the payload that
   *                are used by the algorithm?
   * @return Array the payload inside it or null if the sig is wrong
   */
  protected function parseSignedRequest($signed_request) {
    list($encoded_sig, $payload) = explode('.', $signed_request, 2);

    // decode the data
    $sig = self::base64UrlDecode($encoded_sig);
    $data = json_decode(self::base64UrlDecode($payload), true);

    if (strtoupper($data['algorithm']) !== 'HMAC-SHA256') {
      self::errorLog('Unknown algorithm. Expected HMAC-SHA256');
      return null;
    }

    // check sig
    $expected_sig = hash_hmac('sha256', $payload,
                              $this->getApiSecret(), $raw = true);
    if ($sig !== $expected_sig) {
      self::errorLog('Bad Signed JSON signature!');
      return null;
    }

    return $data;
  }

  /**
   * Build the URL for api given parameters.
   *
   * @param $method String the method name.
   * @return String the URL for the given parameters
   */
  protected function getApiUrl($method) {
    static $READ_ONLY_CALLS =
      array('admin.getallocation' => 1,
            'admin.getappproperties' => 1,
            'admin.getbannedusers' => 1,
            'admin.getlivestreamvialink' => 1,
            'admin.getmetrics' => 1,
            'admin.getrestrictioninfo' => 1,
            'application.getpublicinfo' => 1,
            'auth.getapppublickey' => 1,
            'auth.getsession' => 1,
            'auth.getsignedpublicsessiondata' => 1,
            'comments.get' => 1,
            'connect.getunconnectedfriendscount' => 1,
            'dashboard.getactivity' => 1,
            'dashboard.getcount' => 1,
            'dashboard.getglobalnews' => 1,
            'dashboard.getnews' => 1,
            'dashboard.multigetcount' => 1,
            'dashboard.multigetnews' => 1,
            'data.getcookies' => 1,
            'events.get' => 1,
            'events.getmembers' => 1,
            'fbml.getcustomtags' => 1,
            'feed.getappfriendstories' => 1,
            'feed.getregisteredtemplatebundlebyid' => 1,
            'feed.getregisteredtemplatebundles' => 1,
            'fql.multiquery' => 1,
            'fql.query' => 1,
            'friends.arefriends' => 1,
            'friends.get' => 1,
            'friends.getappusers' => 1,
            'friends.getlists' => 1,
            'friends.getmutualfriends' => 1,
            'gifts.get' => 1,
            'groups.get' => 1,
            'groups.getmembers' => 1,
            'intl.gettranslations' => 1,
            'links.get' => 1,
            'notes.get' => 1,
            'notifications.get' => 1,
            'pages.getinfo' => 1,
            'pages.isadmin' => 1,
            'pages.isappadded' => 1,
            'pages.isfan' => 1,
            'permissions.checkavailableapiaccess' => 1,
            'permissions.checkgrantedapiaccess' => 1,
            'photos.get' => 1,
            'photos.getalbums' => 1,
            'photos.gettags' => 1,
            'profile.getinfo' => 1,
            'profile.getinfooptions' => 1,
            'stream.get' => 1,
            'stream.getcomments' => 1,
            'stream.getfilters' => 1,
            'users.getinfo' => 1,
            'users.getloggedinuser' => 1,
            'users.getstandardinfo' => 1,
            'users.hasapppermission' => 1,
            'users.isappuser' => 1,
            'users.isverified' => 1,
            'video.getuploadlimits' => 1);
    $name = 'api';
    if (isset($READ_ONLY_CALLS[strtolower($method)])) {
      $name = 'api_read';
    }
    return self::getUrl($name, 'restserver.php');
  }

  /**
   * Build the URL for given domain alias, path and parameters.
   *
   * @param $name String the name of the domain
   * @param $path String optional path (without a leading slash)
   * @param $params Array optional query parameters
   * @return String the URL for the given parameters
   */
  protected function getUrl($name, $path='', $params=array()) {
    $url = self::$DOMAIN_MAP[$name];
    if ($path) {
      if ($path[0] === '/') {
        $path = substr($path, 1);
      }
      $url .= $path;
    }
    if ($params) {
      $url .= '?' . http_build_query($params, null, '&');
    }
    return $url;
  }

  /**
   * Returns the Current URL, stripping it of known FB parameters that should
   * not persist.
   *
   * @return String the current URL
   */
  protected function getCurrentUrl() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on'
      ? 'https://'
      : 'http://';
    $currentUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    $parts = parse_url($currentUrl);

    // drop known fb params
    $query = '';
    if (!empty($parts['query'])) {
      $params = array();
      parse_str($parts['query'], $params);
      foreach(self::$DROP_QUERY_PARAMS as $key) {
        unset($params[$key]);
      }
      if (!empty($params)) {
        $query = '?' . http_build_query($params, null, '&');
      }
    }

    // use port if non default
    $port =
      isset($parts['port']) &&
      (($protocol === 'http://' && $parts['port'] !== 80) ||
       ($protocol === 'https://' && $parts['port'] !== 443))
      ? ':' . $parts['port'] : '';

    // rebuild
    return $protocol . $parts['host'] . $port . $parts['path'] . $query;
  }

  /**
   * Generate a signature for the given params and secret.
   *
   * @param Array $params the parameters to sign
   * @param String $secret the secret to sign with
   * @return String the generated signature
   */
  protected static function generateSignature($params, $secret) {
    // work with sorted data
    ksort($params);

    // generate the base string
    $base_string = '';
    foreach($params as $key => $value) {
      $base_string .= $key . '=' . $value;
    }
    $base_string .= $secret;

    return md5($base_string);
  }

  /**
   * Prints to the error log if you aren't in command line mode.
   *
   * @param String log message
   */
  protected static function errorLog($msg) {
    // disable error log if we are running in a CLI environment
    // @codeCoverageIgnoreStart
    if (php_sapi_name() != 'cli') {
      error_log($msg);
    }
    // uncomment this if you want to see the errors on the page
    // print 'error_log: '.$msg."\n";
    // @codeCoverageIgnoreEnd
  }

  /**
   * Base64 encoding that doesn't need to be urlencode()ed.
   * Exactly the same as base64_encode except it uses
   *   - instead of +
   *   _ instead of /
   *
   * @param String base64UrlEncodeded string
   */
  protected static function base64UrlDecode($input) {
    return base64_decode(strtr($input, '-_', '+/'));
  }
}

endif; // if !class_exists('Facebook')
// src/core.php

 
/**
 * coreylib - Core functionality.
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
 
/**
 * Generic Exception wrapper
 */
class clException extends Exception {}
 
/**
 * The entry point for all parsing.
 */
class clApi {
  
  const METHOD_GET = 'get';
  const METHOD_POST = 'post';
  
  function __construct($url) {
    
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP GET.
   * @param string $cache_for An expression of time
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function parse($cache_for) {
    
  }
  
  /**
   * Download and parse the data from the specified endpoint using an HTTP POST.
   * @param string $cache_for An expression of time
   * @return bool TRUE if parsing succeeds; otherwise FALSE.
   * @see http://php.net/manual/en/function.strtotime.php
   */
  function post($cache_for) {
    
  }
  
  /**
   * Print the content of the parsed document.
   */
  function __toString() {
    
  }
  
  function info() {
    
  }
  
  /**
   * Provide access to the wrapped SimpleXML object.
   */
  function __get($prop_name) {
    
  }
  
  /**
   * Provide help to users of older versions.
   */
  function __call($fx_name, $args) {
    
    
  }
  
}

if (!function_exists('coreylib')):
  function coreylib($url, $cache_for = null, $params = array(), $method = clApi::METHOD_GET) {
    $api = new clApi($url);
  }
endif;

// src/node.php


/**
 * coreylib - Standard API for navigating data: XML and JSON
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

/**
 * Parser for jQuery-inspired selector syntax.
 */
class clSelector implements ArrayAccess, Iterator {
  
  static $sep = "#(\s+|/)#";
  
  static $regex;
  
  static $attrib_exp;
  
  private $selectors = array();
  
  private $i = 0;
  
  static $tokenize = array('#', ';', '&', ',', '.', '+', '*', '~', "'", ':', '"', '!', '^', '$', '[', ']', '(', ')', '=', '>', '|', '/', '@', ' ');
  
  private $tokens;
  
  function __construct($query, $direct = null) {
    if (!self::$regex) {
      self::$regex = self::generateRegEx();
    }

    if ($query == '*') {
      $selectors = array('*');
    } else {
      $tokenized = $this->tokenize($query);
      if (!($selectors = preg_split(self::$sep, $tokenized))) {
        throw new clException("Failed to parse selector query [$query].");
      }
    } 
    
    foreach($selectors as $sel) {
      if (!preg_match(self::$regex, $sel, $matches)) {
        throw new clException("Failed to parse [$sel], part of query [$query].");
      }
      
      $sel = (object) array(
        'element' => $this->untokenize(@$matches['element']),
        'is_expression' => ($this->untokenize(@$matches['attrib_exp']) != false),
        // in coreylib v1, passing "@attributeName" retrieved a scalar value;
        'is_attrib_getter' => preg_match('/^@.*$/', $query),
        // defaults for these:
        'attrib' => null,
        'value' => null,
        'suffixes' => null,
        'test' => null,
        'direct_descendants' => (!is_null($direct)) ? $direct : false
      );
      
      // default element selection is "all," as in all children of current node
      if (!$sel->element && !$sel->is_attrib_getter) {
        $sel->element = '*';
      }
      
      if ($exp = @$matches['attrib_exp']) {
        // multiple expressions?
        if (strpos($exp, '][') !== false) {
          $attribs = array();
          $values = array();
          $tests = array();
          
          $exps = explode('][', substr($exp, 1, strlen($exp)-2));
          foreach($exps as $exp) {
            if (preg_match('#'.self::$attrib_exp.'#', "[{$exp}]", $matches)) {
              $attribs[] = $matches['attrib_exp_name'];
              $tests[] = $matches['test'];
              $values[] = $matches['value'];
            }
          }
          
          $sel->attrib = $attribs;
          $sel->value = $values;
          $sel->test = $tests;
        // just one expression
        } else {
          $sel->attrib = array($this->untokenize(@$matches['attrib_exp_name']));
          $sel->value = array($this->untokenize(@$matches['value']));
          $sel->test = array(@$matches['test']);
        }
      // no expression
      } else {
        $sel->attrib = $this->untokenize(@$matches['attrib']);
      }
      
      if ($suffixes = @$matches['suffix']) {
        $all = array_filter(explode(':', $suffixes));
        $suffixes = array();
        
        foreach($all as $suffix) {
          $open = strpos($suffix, '(');
          $close = strrpos($suffix, ')');
          if ($open !== false && $close !== false) {
            $label = substr($suffix, 0, $open);
            $val = $this->untokenize(substr($suffix, $open+1, $close-$open-1));
          } else {
            $label = $suffix;
            $val = true;
          }
          $suffixes[$label] = $val;
        }
        
        $sel->suffixes = $suffixes;
      }
      
      // alias for eq(), and backwards compat with coreylib v1
      if (!isset($sel->suffixes['eq']) && ($index = @$matches['index'])) {
        $sel->suffixes['eq'] = $index;
      }
      
      $this->selectors[] = $sel;
    }
  }
  
  private function tokenize($string) {
    $tokenized = false;
    foreach(self::$tokenize as $t) {
      while(($at = strpos($string, "\\$t")) !== false) {
        $tokenized = true;
        $token = "TKS".count($this->tokens)."TKE";
        $this->tokens[] = $t;
        $string = substr($string, 0, $at).$token.substr($string, $at+2);
      }
    }
    return $tokenized ? 'TK'.$string : $string;
  }
  
  private function untokenize($string) {
    if (!$string || strpos($string, 'TK') !== 0) {
      return $string;
    } else {
      foreach($this->tokens as $i => $t) {
        $token = "TKS{$i}TKE";
        $string = preg_replace("/{$token}/", $t, $string);
      }
      return substr($string, 2);
    }
  }
  
  function __get($name) {
    $sel = $this->selectors[$this->i];
    return $sel->{$name};
  }
  
  function has_suffix($name) {
    $sel = $this->selectors[$this->i];
    return @$sel->suffixes[$name];
  }
  
  function index() {
    return $this->i;
  }
  
  function size() {
    return count($this->selectors);
  }
  
  function current() {
    return $this->selectors[$this->i];
  }
  
  function key() {
    return $this->i;
  }
  
  function next() {
    $this->i++;
  }
  
  function rewind() {
    $this->i = 0;
  }
  
  function valid() {
    return isset($this->selectors[$this->i]);
  }
  
  function offsetExists($offset) {
    return isset($this->selectors[$offset]);
  }
  
  function offsetGet($offset) {
    return $this->selectors[$offset];
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clSelector objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clSelector objects are read-only.");
  }
  
  function getSelectors() {
    return $this->selectors;
  }
  
  static function generateRegEx() {
    // characters comprising valid names
    // should not contain any of the characters in self::$tokenize
    $name = '[A-Za-z0-9\_\-]+';
    
    // element express with optional index
    $element = "((?P<element>(\\*|{$name}))(\\[(?P<index>[0-9]+)\\])?)";
    
    // attribute expression 
    $attrib = "@(?P<attrib>{$name})";
    
    // tests of equality
    $tests = implode('|', array(
      // Selects elements that have the specified attribute with a value either equal to a given string or starting with that string followed by a hyphen (-).
      "\\|=",
      // Selects elements that have the specified attribute with a value containing the a given substring.
      "\\*=",
      // Selects elements that have the specified attribute with a value containing a given word, delimited by whitespace.
      "~=",
      // Selects elements that have the specified attribute with a value ending exactly with a given string. The comparison is case sensitive.
      "\\$=",
      // Selects elements that have the specified attribute with a value exactly equal to a certain value.
      "=",
      // Select elements that either don't have the specified attribute, or do have the specified attribute but not with a certain value.
      "\\!=",
      // Selects elements that have the specified attribute with a value beginning exactly with a given string.
      "\\^="
    ));
    
    // suffix selectors
    $suffixes = implode('|', array(
      // retun nth element
      ":eq\\([0-9]+\\)",
      // return the first element
      ":first",
      // return the last element
      ":last",
      // greater than index
      ":gt\\([0-9]+\\)",
      // less than index
      ":lt\\([0-9]+\\)",
      // even only
      ":even",
      // odd only
      ":odd",
      // empty - no children, no text
      ":empty",
      // parent - has children: text nodes count
      ":parent",
      // has - contains child element
      ":has\\([^\\)]+\\)",
      // text - text node in the element is
      ":contains\\([^\\)]+\\)"
    ));
    
    $suffix_exp = "(?P<suffix>({$suffixes})+)";
    
    // attribute expression
    self::$attrib_exp = $attrib_exp = "\\[@?((?P<attrib_exp_name>{$name})((?P<test>{$tests})\"(?P<value>.*)\")?)\\]";
    
    // the final expression
    return "#^{$element}?(({$attrib})|(?P<attrib_exp>{$attrib_exp}))*{$suffix_exp}*$#";
  }
  
}

class clNodeArray implements ArrayAccess, Iterator {
  
  private $arr = array();
  private $i;
  
  function __construct($arr = null) {
    if (!is_null($arr)) {
      if ($arr instanceof clNodeArray) {
        $this->arr = $arr->toArray();
      } else {
        $this->arr = $arr;
      }
    }
  }
  
  function toArray() {
    return $this->arr;
  }
  
  function __get($name) {
    if ($node = @$this->arr[0]) {
      return $node->{$name};
    } else {
      return null;
    }
  }
  
  function __call($name, $args) {
    if (($node = @$this->arr[0]) && is_object($node)) {
      return call_user_func_array(array($node, $name), $args);
    } else if (!is_null($node)) {
      throw new Exception("Value in clNodeArray at index 0 is not an object.");
    }
  }
  
  function size() {
    return count($this->arr);
  }
  
  /**
   * Run a selector query on the direct descendants of these nodes.
   */
  function children($selector = '') {
    $sel = $selector;
    if (!is_object($sel)) {
      $sel = new clSelector($sel, true);
    }
    
    $children = array();
    foreach($this->$arr as $node) {
      $children = array_merge($children, $node->get($sel));
      $sel->rewind();
    }
    
    return new clNodeArray($children);
  }
  
  function current() {
    return $this->arr[$this->i];
  }
  
  function key() {
    return $this->i;
  }
  
  function next() {
    $this->i++;
  }
  
  function rewind() {
    $this->i = 0;
  }
  
  function valid() {
    return isset($this->arr[$this->i]);
  }
  
  function offsetExists($offset) {
    if (is_string($offset)) {
      if ($node = @$this->arr[0]) {
        return isset($node[$offset]);
      } else {
        return false;
      }
    } else {
      return isset($this->arr[$offset]);
    }
  }
  
  function offsetGet($offset) {
    if (is_string($offset)) {
      if ($node = @$this->arr[0]) {
        return @$node[$offset];
      } else {
        return null;
      }
    } else {
      return @$this->arr[$offset];
    }
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clNodeArray objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clNodeArray objects are read-only.");
  }
  
  function __toString() {
    if ($node = @$this->arr[0]) {
      return (string) $node;
    } else {
      return '';
    }
  }
  
}

/**
 * Models a discreet unit of data. This unit of data can have attributes (or properties)
 * and children, themselves instances of clNode. Implements ArrayAccess, exposing attribute()
 * function.
 */
abstract class clNode implements ArrayAccess {
  
  /**
   * Factory method: return the correct type of clNode.
   * @param $string The content to parse
   * @param string $type The type - supported include "xml" and "json"
   * @return clNode implementation 
   */
  function getNodeFor($string, $type) {
    if ($type == 'xml') {
      $node = new clXmlNode();
    } else if ($type == 'json') {
      $node = new clJsonNode();
    } else {
      throw new clException("Unsupported Node type: $type");
    }
    
    if (!$node->parse($string)) {
      return false;
    } else {
      return $node;
    }
  }
  
  function offsetExists($offset) {
    $att = $this->attribute($offset);
    return !is_null($att);
  }
  
  function offsetGet($offset) {
    return $this->attribute($offset);
  }
  
  function offsetSet($offset, $value) {
    throw new clException("clNode objects are read-only.");
  }
  
  function offsetUnset($offset) {
    throw new clException("clNode objects are read-only.");
  }
  
  /**
   * Retrieve the first element or attribute queried by $selector.
   * @param string $selector
   * @return mixed an instance of a clNode subclass, or a scalar value
   * @throws clException When an attribute requested does not exist.
   */ 
  function first($selector) {
    $values = $this->get($selector);
    return is_array($values) ? @$values[0] : $values;
  }
  
  /**
   * Retrieve the last element or attribute queried by $selector.
   * @param string $selector
   * @return mixed an instance of a clNode subclass, or a scalar value
   * @throws clException When an attribute requested does not exist.
   */ 
  function last($selector) {
    $values = $this->get($selector);
    return is_array($values) ? @array_pop($values) : $values;
  }
  
  /**
   * Retrieve some data from this Node and/or its children.
   * @param mixed $selector A query conforming to the coreylib selector syntax, or an instance of clSelector
   * @param int $limit A limit on the number of values to return
   * @param array &$results Results from the previous recursive iteration of ::get
   * @return mixed A clNodeArray or a single value, given to $selector.
   */
  function get($selector, $limit = null, &$results = null) {
    // shorten the variable name, for convenience
    $sel = $selector;
    if (!is_object($sel)) {
      $sel = new clSelector($sel);
      if (!$sel->valid()) {
        // nothing to process
        return new clNodeArray();
      }
    }
    
    if (is_null($results)) {
      $results = array($this);
    } else if (!is_array($results)) {
      $results = array($results);
    } 
    
    if ($sel->element) {
      $agg = array();
      foreach($results as $child) {
        if (is_object($child)) {
          $agg = array_merge($agg, $child->children($sel->element));
        }
      }
      $results = $agg;
      
      if (!count($results)) {
        return new clNodeArray();
      }
    } 
    
    if ($sel->attrib) {
      if ($sel->is_expression) {
        $agg = array();
        foreach($results as $child) {
          if ($child->has_attribute($sel->attrib, $sel->test, $sel->value)) {
            $agg[] = $child;
          }
        }
        $results = $agg;
        
      } else {
        $agg = array();
        foreach($results as $child) {
          if (is_object($child)) {
            $att = $child->attribute($sel->attrib);
            if (is_array($att)) {
              $agg = array_merge($agg, $att);
            } else {
              $agg[] = $att;
            }
          }
        }
        
        // remove empty values and reset index
        $agg = array_values(array_filter($agg));
        
        if ($sel->is_attrib_getter) {
          return @$agg[0];
        } else {
          $results = $agg;
        }
      }
      
      if (!count($results)) {
        return new clNodeArray();
      }
    }
    
    if ($sel->suffixes) {
      foreach($sel->suffixes as $suffix => $val) { 
        if ($suffix == 'gt') {
          $results = array_slice($results, $index);
        
        } else if ($suffix == 'lt') {
          $results = array_reverse(array_slice(array_reverse($results), $index));
      
        } else if ($suffix == 'first') {
          $results = array(@$results[0]);
      
        } else if ($suffix == 'last') {
          $results = array(@array_pop($results));
        
        } else if ($suffix == 'eq') {
          $results = array(@$results[$val]);

        } else if ($suffix == 'empty') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (!count($r->children()) && ((string) $r) == '') {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
        
        } else if ($suffix == 'parent') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (((string) $r) != '' || count($r->children())) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'has') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (count($r->children($val))) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'contains') {
          $agg = array();
          foreach($results as $r) {
            if (is_object($r)) {
              if (strpos((string) $r, $val) !== false) {
                $agg[] = $r;
              }
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'even') {
          $agg = array();
          foreach($results as $i => $r) {
            if ($i % 2 === 0) {
              $agg[] = $r;
            }
          }
          $results = $agg;
          
        } else if ($suffix == 'odd') {
          $agg = array();
          foreach($results as $i => $r) {
            if ($i % 2) {
              $agg[] = $r;
            }
          }
          $results = $agg;
          
        }
      }
      
      if (!count($results)) {
        return new clNodeArray();
      }
    }
      
    // recursively use ::get to draw the lowest-level values
    $sel->next();
    if ($sel->valid()) {
      $results = $this->get($sel, null, $results);
    }  
    
    // limit, if requested
    if ($limit && is_array($results)) {
      $results = array_slice($results, 0, $limit);
    }
    
    return new clNodeArray($results);
  }
  
  /**
   * Should return either an array or a single value, given to $selector:
   * if selector is undefined, return an array of all attributes as a 
   * hashtable; otherwise, return the attribute's value, or if the attribute
   * does not exist, return null.
   * @param string $selector
   * @param mixed array, a single value, or null
   */
  protected abstract function attribute($selector = '');
  
  /**
   * Determines if the given $selectors, $tests, and $values are true.
   * @param mixed $selectors a String or an array of strings, matching attributes by name
   * @param mixed $tests a String or an array of strings, each a recognized comparison operator (e.g., = or != or $=)
   * @param mixed $values a String or an array of strings, each a value to be matched according to the corresponding $test
   * @return true when all tests are true; otherwise, false
   */
  protected function has_attribute($selectors = '', $tests = null, $values = null) {
    // convert each parameter to an array
    if (!is_array($selectors)) {
      $selectors = array($selectors);
    }
    if (!is_array($tests)) {
      $tests = array($tests);
    }
    if (!is_array($values)) {
      $values = array($values);
    }
    
    // get all attributes
    $atts = $this->attribute();
    // no attributes? all results false
    if (!count($atts)) {
      return false;
    }
    
    $result = true;
    
    foreach($selectors as $i => $selector) {
      $selected = @$atts[$selector];
      $value = @$values[$i];
      $test = @$tests[$i];
    
      // all tests imply presence
      if (empty($selected)) {
        $result = false;
      // equal
      } else if ($test == '=') {
        $result =  $selected == $value;
      // not equal
      } else if ($test == '!=') {
        $result =  $selected != $value;
      // prefix
      } else if ($test == '|=') {
        $result =  $selected == $value || strpos($selected, "{$value}-") === 0;
      // contains
      } else if ($test == '*=') {
        $result =  strpos($selected, $value) !== false;
      // space-delimited word
      } else if ($test == '~=') {
        $words = preg_split('/\s+/', $selected);
        $result =  in_array($value, $words);
      // ends with
      } else if ($test == '$=') {
        $result =  strpos(strrev($selected), strrev($value)) === 0;
      // starts with
      } else if ($test == '^=') {
        $result =  strpos($selected, $value) === 0;
      }
      
      if ($result == false) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Retrieve a list of the child elements of this node. Unless $direct is true,
   * child elements should include ALL of the elements that appear beneath this element,
   * flattened into a single list, and in document order. If $direct is true,
   * only the direct descendants of this node should be returned.
   * @param string $selector
   * @param boolean $direct (Optional) defaults to false
   * @return array
   */
   
  protected abstract function descendants($selector = '', $direct = false);
  
  /**
   * Should respond with the value of this node, whatever that is according to
   * the implementation. 
   */
  abstract function __toString();
  
  /**
   * Initialize this node from the data represented by an arbitrary string.
   * @param string $string
   */
  abstract function parse($string = '');
  
}

/**
 * JSON implementation of clNode, wraps the results of json_decode.
 */
class clJsonNode extends clNode {
  
  private $obj;
  
  function __construct(&$json_object = null) {
    $this->obj = $json_object;
  }
  
  function parse($string = '') {
    
  }
  
  protected function descendants($selector = '', $direct = false) {
    
  }
  
  protected function attribute($selector = '') {
    
  }
  
  function __toString() {
    return '';
  }
  
}

/**
 * XML implementation of clNode, wraps instances of SimpleXMLElement.
 */
class clXmlNode extends clNode {
  
  private $el;
  private $ns;
  private $namespaces;
  private $descendants;
  private $attributes;
  
  /**
   * Wrap a SimpleXMLElement object.
   * @param SimpleXMLElement $simple_xml_el (optional) defaults to null
   * @param clXmlNode $parent (optional) defaults to null
   * @param string $ns (optional) defaults to empty string
   * @param array $namespaces (optional) defaults to null
   */
  function __construct(&$simple_xml_el = null, $parent = null, $ns = '', &$namespaces = null) {
    $this->el = $simple_xml_el;
    $this->parent = $parent;
    $this->ns = $ns;
    
    if (!is_null($namespaces)) {
      $this->namespaces = $namespaces;
    }
    
    if (!$this->namespaces && $this->el) {
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
    }
  }
  
  function parse($string = '') {
    if (($sxe = simplexml_load_string(trim($string))) !== false) {
      $this->el = $sxe;
      $this->namespaces = $this->el->getNamespaces(true);
      $this->namespaces[''] = null;
      return true;
    } else {
      // TODO: in PHP >= 5.1.0, it's possible to silence SimpleXML parsing errors and then iterate over them
      // http://us.php.net/manual/en/function.simplexml-load-string.php
      return false;
    }
  }
  
  function namespace() {
    return $this->ns;
  }
  
  function parent() {
    return $this->parent;
  }
  
  /**
   * Expose the SimpleXMLElement API.
   */
  function __call($fx_name, $args) {
    $result = call_user_func_array(array($this->el, $fx_name), $args);
    if ($result instanceof SimpleXMLElement) {
      return new clXmlNode($result, $this, '', $this->namespaces);
    } else {
      return $result;
    }
  }
  
  /**
   * Expose the SimpleXMLElement API.
   */
  function __get($name) {
    $result = $this->el->{$name};
    if ($result instanceof SimpleXMLElement) {
      return new clXmlNode($result, $this, '', $this->namespaces);
    } else {
      return $result;
    }
  }
  
  
  protected function descendants($selector = '', $direct = false) {    
    if (!$this->descendants) {
      $this->descendants = array();
      foreach($this->namespaces as $ns => $uri) {
        foreach($this->el->children($ns, true) as $child) {
          $node = new clXmlNode($child, $this, $ns, $this->namespaces);
          $this->descendants[] = $node;
          $this->descendants = array_merge($this->descendants, $node->descendants('*'));
        }
      }
    }
    
    @list($ns, $name) = explode(':', $selector);
    
    if (!$name) {
      $name = $ns;
      $ns = null;
    }
    
    $children = array();
    
    foreach($this->descendants as $child) {
      if ( (!$name || $name == '*' || $child->getName() == $name) && (!$direct || $child->parent() === $this) && (!$ns || $child->ns() == $ns) ) {
        $children[] = $child;
      }
    }
    
    return $children;
  }
  
  
  protected function attribute($selector = '') {
    if (!$this->attributes) {
      $this->attributes = array();
      foreach($this->namespaces as $ns => $uri) {
        $this->attributes[$ns] = $this->el->attributes($ns, true);
      }
    }
    
    @list($ns, $name) = explode(':', $selector);
    
    if (!$name) {
      $name = $ns;
      $ns = null;
    }
    
    // no name? get all.
    if (!$name) {
      $attributes = array();
      foreach($this->attributes as $ns => $atts) {
        foreach($atts as $this_name => $val) {
          if ($ns) {
            $this_name = "$ns:$this_name";
          }
          $attributes[$this_name] = (string) $val;
        }
      }
      return $attributes;
      
    // ns specified? 
    } else if ($ns && isset($this->attributes[$ns])) {
      foreach($this->attributes[$ns] as $this_name => $val) {
        if ($this_name == $name) {
          return (string) $val;
        }
      }
     
    // looking for the name across all namespaces
    } else {
      foreach($this->attributes as $ns => $atts) {
        foreach($atts as $this_name => $val) {
          if ($this_name == $name) {
            return (string) $val;
          }
        }
      }
    }
    
    return null;
  }
  
  /**
   * Use XPATH to select elements. But... why? Ugh.
   * @param 
   * @return clXmlNode
   * @deprecated Use clXmlNode::get($selector, true) instead.
   */
  function xpath($selector) {
    return new clXmlNode($this->el->xpath($selector), $this, '', $this->namespaces);
  }
  
  function __toString() {
    return (string) $this->el;
  }
  
  function info() {
    
  }
  
}
