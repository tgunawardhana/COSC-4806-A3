<?php
if (isset($_SESSION['auth']) == 1) {
    header('Location: /home');
}


// Login validations
$failed = "";
$success = "";

  
    if (isset($_SESSION['signup_complete']) && $_SESSION['signup_complete'] == 1) {
      $success = "User registered successfully.";
      $_SESSION['signup_complete'] = 0;
    }
    else if (isset($_SESSION['userlocked']) && $_SESSION['userlocked'] == 1){
      $failed = "User is locked. Please try again after 1 minute.";
      $_SESSION['userlocked'] = 0;
    }
      
// Sign up validations
    else if (isset($_SESSION['error_signup']) && $_SESSION['error_signup'] == 1) {
        $failed = "Username or password cannot be empty.";
        $_SESSION['error_signup'] = 0;
    }
    else if (isset($_SESSION['error_signup']) && $_SESSION['error_signup'] == 2) {
        $failed = "Password should be atleast 10 characters long.";
        $_SESSION['error_signup'] = 0;
    }
    else if (isset($_SESSION['error_signup']) && $_SESSION['error_signup'] == 3) {
        $failed = "Passwords does not match. Try again.";
        $_SESSION['error_signup'] = 0;
      }
    else if (isset($_SESSION['error_signup']) && $_SESSION['error_signup'] == 4) {
        $failed = "Username exists. Try another one";
        $_SESSION['error_signup'] = 0;
      }
    else {
      $failed = "";
      $success = "";
    }

?>

<!DOCTYPE html>
<html lang="en">
    <link href="app/views/templates/styles.css" rel="stylesheet">
    <link rel="icon" href="/favicon.png">
    <title>COSC 4806</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="mobile-web-app-capable" content="yes">
</head>
<body>