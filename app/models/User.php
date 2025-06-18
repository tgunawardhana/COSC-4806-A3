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
			header('Location: /home');
			die;
		} else {
			if(isset($_SESSION['failedAuth'])) {
				$_SESSION['failedAuth'] ++; //increment
        
			} else {
				$_SESSION['failedAuth'] = 1;
			}
			header('Location: /login');
			die;
		}
    }


  public function get_user_by_username($username) {
    $dbh = db_connect();
    $statement = $dbh->prepare("select * from users where username = :username;");
    $statement->bindParam(':username', $username);
    $statement->execute();
    $row = $statement->fetch(PDO::FETCH_ASSOC);
    return $row;
  }

  public function register_user($username, $password) {

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $existing_user_data = $this->get_user_by_username($username);

    if ($existing_user_data && $existing_user_data['username'] == $username)  {
      $_SESSION['error_signup'] = 4;
      header("location: /signup");
      die();
    }
    else {

      $dbh = db_connect();
      $statement = $dbh->prepare("insert into users (username, password) values (:username, :password);");
      $statement->bindParam(':username', $username);
      $statement->bindParam(':password', $hashed_password);
      $statement->execute();
      $_SESSION['signup_complete'] = 1;
      header("location: /login");
      die();
    }
  }
  

  
}
