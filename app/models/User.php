<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }

    public function test () {
      $db = db_connect();
      $statement = $db->prepare("select * from users;");
      $statement->execute();
      $rows = $statement->fetch(PDO::FETCH_ASSOC);
      return $rows;
    }

    public function attemptlog($username, $status){
        $db = db_connect();
      $statement = $db->prepare("insert into login_attempts (username, status) VALUES (:username, :status);");
      $statement->bindParam(':username', $username);
      $statement->bindParam(':status', $status);
      $statement->execute();
    }

    public function authenticate($username, $password) {
        /*
         * if username and password good then
         * $this->auth = true;
         */
  		$username = strtolower($username);
  		$db = db_connect();
          $statement = $db->prepare("select * from users WHERE username = :name;");
          $statement->bindValue(':name', $username);
          $statement->execute();
          $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		
  		if (password_verify($password, $rows['password'])) {
  			$_SESSION['auth'] = 1;
  			$_SESSION['username'] = ucwords($username);
  			unset($_SESSION['failedAuth']);
        $this->attemptlog($username, 'success');
  			header('Location: /home');
  
  			die;
  		} else {
  			if(isset($_SESSION['failedAuth'])) {
  				$_SESSION['failedAuth'] ++; //increment
          
  			} else {
  				$_SESSION['failedAuth'] = 1;
  			}
        
        $this->attemptlog($username, 'failed');
  			header('Location: /login');
  			die;
  		}
    }


  
  

  
}
