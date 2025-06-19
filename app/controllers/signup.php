<?php

class Signup extends Controller {

    public function index() {		
        $this->view('signup/index');
    }
    
    public function create(){
        $username = $_REQUEST['username'];
        $password = $_REQUEST['password'];
        $password2 = $_REQUEST['password2'];
        
        if ($username == "" || $password == "") {
          $_SESSION['error_signup'] = 1;
          header("location: /signup");
          exit();
        }
        
        else if (strlen($password) < 10){
          $_SESSION['error_signup'] = 2;
          header("location: /signup");
          die();
        }
        else if ($password != $password2){
          $_SESSION['error_signup'] = 3;
          header("location: /signup");
          die();
        }

        $_SESSION['failed'] = 0;
        $signupUser = $this->model('Register');
        $signupUser->register_user($username, $password); 
        
    }
  
}