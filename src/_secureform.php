<?php

class SecureForm {

  public function __construct(){
    if(isset($_SESSION) && !empty($_SESSION)){
      return true;
    } else {
      session_start();
    }
  }

  // Should be private
  public function getRealIp() {
    if ( function_exists('apache_request_headers') ) {
      $headers = apache_request_headers();
    } else {
      $headers = $_SERVER;
    }
  
    if ( array_key_exists( 'X-Forwarded-For', $headers ) && filter_var( $headers['X-Forwarded-For'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
      $the_ip = $headers['X-Forwarded-For'] . " (X-Forwarded-For)";
    } elseif ( array_key_exists( 'HTTP_X_FORWARDED_FOR', $headers ) && filter_var( $headers['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
      $the_ip = $headers['HTTP_X_FORWARDED_FOR'] . "(HTTP_X_FORWARDED_FOR)";
    } elseif ( array_key_exists( 'REMOTE_ADDR', $headers ) ) {
      $the_ip = filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
    } else {
      $the_ip = getenv('HTTP_CLIENT_IP')?:
                getenv('HTTP_X_FORWARDED')?:
                getenv('HTTP_FORWARDED_FOR')?:
                getenv('HTTP_FORWARDED')?:
                getenv('REMOTE_ADDR')?:
                'unknown';
    }
    
    return filter_var( $the_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
  }

  public function generateToken($id='default') {

    // generate a token from an unique value, took from microtime, you can also use salt-values, other crypting methods...
    $token = md5(uniqid(microtime(), true));  
  
    // Write the generated token to the session variable to check it against the hidden field when the form is sent
    if(isset($_SESSION)){
      $_SESSION[$id.'_token'] = $token;
    }
  
    return $token;
  }

  public function verifyToken($id='default') {
    // check if a session is started and a token is transmitted, if not return an error
    if(!isset($_SESSION[$form.'_token'])) { 
      return false;
    }
  
    // check if the form is sent with token in it
    if(!isset($_POST['token'])) {
      return false;
    }
  
    // compare the tokens against each other if they are still the same
    if ($_SESSION[$form.'_token'] !== $_POST['token']) {
      return false;
    }
  
    return true;
  }

}