package com.demo.jwtauthentication.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.demo.jwtauthentication.model.RequestPassword;

/**
 * @author Arun Kumar M N
 * 30-May-2019 6:40:17 PM
 */
@Repository
public interface RequestPasswordRepository  extends JpaRepository<RequestPassword, Integer>{

}
