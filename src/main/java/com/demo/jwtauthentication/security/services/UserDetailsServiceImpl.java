package com.demo.jwtauthentication.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.demo.jwtauthentication.model.User;
import com.demo.jwtauthentication.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {
    	 System.out.println("Started LoadUserByEmail="+email);
         System.out.println(userRepository.findByEmail(email));
         	User user=userRepository.findByEmail(email);
          
         	if(user==null) {
         		return null;
         	}
      /*   User user = userRepository.findByEmail(email)
                	.orElseThrow(() -> 
                        new UsernameNotFoundException("User Not Found with -> username or email : " + email)
        );*/
        System.out.println("Ended LoadUserByEmail");
        return UserPrinciple.build(user);
    }
}