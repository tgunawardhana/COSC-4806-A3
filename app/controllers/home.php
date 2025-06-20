<?php

class Home extends Controller {

    public function index() {
      $user = $this->model('User');
			
	    $this->view('home/index');
	    die;
    }

}
