<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }


  public function attemptlog($username, $status){
    $db = db_connect();
    $statement = $db->prepare("insert into login_attempts (username, status) VALUES (:username, :status);");
    $statement->bindParam(':username', $username);
    $statement->bindParam(':status', $status);
    $statement->execute();
  }


  public function isUserLocked($username){
    $db = db_connect();
    $stmt = $db->prepare("select * from login_attempts WHERE username = :username AND status = 'failed' ORDER BY attempt_time DESC LIMIT 3;");
      $stmt->bindValue(':username', $username);
      $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);


    $last_attempt = $rows[2]['attempt_time'];
    $current_time = time();
    $time_diff = $current_time - strtotime($last_attempt);

    if (isset($_SESSION['failedAuth']) && $_SESSION['failedAuth'] > 2) {
      unset($_SESSION['failedAuth']);
      return true;
    }

    if ($time_diff < 60) {
        return true;
    }
    else
        return false;
  }

  
     public function authenticate($username, $password) {

       $username = strtolower($username);
       
       if ($this->isUserLocked($username)) {
          $_SESSION['userlocked'] = 1;
          header('Location: /login');
          exit;
        }
       else{ 
         $username = strtolower($username);
         $db = db_connect();

         unset($_SESSION['userlocked']);
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

 

}