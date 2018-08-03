<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once '_secureform.php';

$myform = new Secureform();

$id = 'myform';

$myform->generateToken($id);

//echo $_SESSION[$id.'_token'];

$headers = '';
if ( function_exists('apache_request_headers') ) {
  $headers = apache_request_headers();
} else {
  $headers = $_SERVER;
}


if        ( array_key_exists( 'X-Forwarded-For', $headers ) && filter_var( $headers['X-Forwarded-For'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
  $the_ip = $headers['X-Forwarded-For'];

} elseif  ( array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers ) && filter_var( $headers['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
  $the_ip = $headers['HTTP_X_FORWARDED_FOR'];

} elseif  ( array_key_exists( 'REMOTE_ADDR', $headers ) ) {
  $the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );

} else {
  $the_ip = getenv('HTTP_CLIENT_IP')?:
            getenv('HTTP_X_FORWARDED')?:
            getenv('HTTP_FORWARDED_FOR')?:
            getenv('HTTP_FORWARDED')?:
            getenv('REMOTE_ADDR')?:
            'unknown';
}

echo "IP ADDRESS: ".$the_ip;