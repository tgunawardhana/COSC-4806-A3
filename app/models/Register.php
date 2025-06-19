<?php

class Register {

  public function __construct() {
  
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