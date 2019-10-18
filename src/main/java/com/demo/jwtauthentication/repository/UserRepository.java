package com.demo.jwtauthentication.repository;


import org.springframework.boot.autoconfigure.data.web.SpringDataWebProperties.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.demo.jwtauthentication.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
	//@Query(value="select * from users where email=?",nativeQuery=true)
  
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
	/**
	 * @param email
	 * @return
	 */
	User findByEmail(String email);
     
}