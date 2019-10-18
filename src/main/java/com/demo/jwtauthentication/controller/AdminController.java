package com.demo.jwtauthentication.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.demo.jwtauthentication.model.User;
import com.demo.jwtauthentication.repository.UserRepository;
import com.demo.jwtauthentication.security.services.UserPrinciple;

/**
 * @author Arun Kumar M N
 * 25-Apr-2019 4:16:12 PM
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class AdminController {
	@Autowired
	UserRepository userRepository;
	 @Autowired
	@Qualifier("sessionRegistry")
	private SessionRegistry sessionRegistry;
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	 @RequestMapping("/getallusers")
	    public List<User> getall(){

		
	    	return userRepository.findAll();
	    }

	

	@PreAuthorize("hasRole('ROLE_ADMIN')")
	 @RequestMapping("/getallusers/active")
	public void getUsersFromSessionRegistry(){
		System.out.println("#Active Users:");
		sessionRegistry.getAllPrincipals().stream().forEach(u->{
			System.out.println(((UserPrinciple)u).getUsername());
		});
	    System.out.println(sessionRegistry.getAllPrincipals().stream()
	      .filter(u -> !sessionRegistry.getAllSessions(u, false).isEmpty())
	      .map(name->((UserPrinciple)name).getUsername())
	      .collect(Collectors.toList()));
	}
}
