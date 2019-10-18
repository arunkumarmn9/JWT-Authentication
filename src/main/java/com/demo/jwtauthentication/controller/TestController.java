package com.demo.jwtauthentication.controller;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.demo.jwtauthentication.repository.UserRepository;

/**
 * @author Arun Kumar M N
 * 18-Mar-2019 1:00:10 PM
 */
@RestController
public class TestController {
	@Autowired
	UserRepository re;
	@PostMapping("/test")
	public String test() {
		String x="arunkumarmn9@gmail.com";
	 
		
		
		return "Tested Success";
	}

}
