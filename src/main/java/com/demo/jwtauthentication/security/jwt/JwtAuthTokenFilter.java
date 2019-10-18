package com.demo.jwtauthentication.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.demo.jwtauthentication.security.services.UserDetailsServiceImpl;
import com.demo.jwtauthentication.security.services.UserPrinciple;

public class JwtAuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtProvider tokenProvider;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
		 
			String jwt = getJwt(request);
			System.out.println(jwt);
			if (jwt != null && tokenProvider.validateJwtToken(jwt)) {
				String Email = tokenProvider.getEmailFromJwtToken(jwt);
				UserDetails userDetails = userDetailsService.loadUserByUsername(Email);
				System.out.println("Authentication Object="+SecurityContextHolder.getContext().getAuthentication());
				if(SecurityContextHolder.getContext().getAuthentication()==null)
				{
				System.out.println("User "+Email+" is not Authenticated so Reauthenticating again!!!");
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				   
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
				}
				else
				{
					
					System.out.println("Seems User "+((UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal())
							.getUser().getEmail()+" is Authenticated");
					System.out.println("Email Obtained From Jwt is "+Email);
					if(((UserPrinciple) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUser().getEmail().equals(Email)) {
					System.out.println("Jwt Verification Success");	
					}
					else {
						//this case for when: logged in user sends the token of another  user(may or may not he authenticated)
						System.out.println("Jwt Verification Failure");
						
					}
				}
			}
		} catch (Exception e) {
			System.out.println("Can NOT set user authentication -> Message: {}");
			logger.error("Can NOT set user authentication -> Message: {}", e);
		}
		filterChain.doFilter(request, response);
	}

	private String getJwt(HttpServletRequest request) {
	
		String authHeader = request.getHeader("Authorization");
		System.out.println("Started getJwt="+authHeader);
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			return authHeader.replace("Bearer ", "");
		}
System.out.println("Ended getJwt");
		return null;
	}
}
