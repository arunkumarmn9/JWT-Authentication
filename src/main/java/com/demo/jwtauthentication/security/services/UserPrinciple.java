package com.demo.jwtauthentication.security.services;

import com.demo.jwtauthentication.model.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class UserPrinciple implements UserDetails {
	private static final long serialVersionUID = 1L;

 User u=new User();

    private Collection<? extends GrantedAuthority> authorities;

    public UserPrinciple(Long id, 
			    		String username, String email, String password, 
			    		Collection<? extends GrantedAuthority> authorities) {
    
    	u.setId(id);
    	u.setUsername(username);
    	u.setEmail(email);
    	u.setPassword(password);
        this.authorities = authorities;
    }

    public static UserPrinciple build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream().map(role ->
                new SimpleGrantedAuthority(role.getName().name())
        ).collect(Collectors.toList());

        return new UserPrinciple(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

 
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
	@Override
	public String getPassword() {
		return u.getPassword();
	}
	 
	@Override
	public String getUsername() {
		
		return u.getUsername();
	}
    public User getUser() {
    	return this.u;
    	 
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        
        UserPrinciple user = (UserPrinciple) o;
        return Objects.equals(this.u.getId(), user.u.getId());
    }
}