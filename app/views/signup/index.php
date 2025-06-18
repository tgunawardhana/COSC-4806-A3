<?php require_once 'app/views/templates/headerPublic.php'?>
<main role="main" class="container">
    <div class="page-header" id="banner">
        <div class="row">
            <div class="col-lg-12">
                <h1>Let's Sign Up</h1>
            </div>
        </div>
    </div>

<div class="row">
    <div class="col-sm-auto">
    <form action="/signup/create" method="post" >
    <fieldset>
      <div class="form-group">
        <label for="username">Username</label>
        <input required type="text" class="form-control" name="username">
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input required type="password" class="form-control" name="password">
      </div>
        
        <div class="form-group">
            <label for="password">Confirm password:</label>
            <input required type="password" class="form-control" name="password2">
          </div>
        
            <br>
        <button type="submit" class="btn btn-primary">Sign Up</button>
    </fieldset>
        <br>
        <p style="color:red;"><?= $failed ?></p>
    </form> 
  </div>
</div>
    <?php require_once 'app/views/templates/footer.php' ?>
