package com.demo.jwtauthentication.controller;

import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.demo.jwtauthentication.message.request.LoginForm;
import com.demo.jwtauthentication.message.request.SignUpForm;
import com.demo.jwtauthentication.model.RequestPassword;
import com.demo.jwtauthentication.model.Role;
import com.demo.jwtauthentication.model.RoleName;
import com.demo.jwtauthentication.model.User;
import com.demo.jwtauthentication.repository.RoleRepository;
import com.demo.jwtauthentication.repository.UserRepository;
import com.demo.jwtauthentication.security.jwt.JwtProvider;
import com.demo.jwtauthentication.security.services.UserDetailsServiceImpl;
import com.demo.jwtauthentication.security.services.UserPrinciple;
import com.demo.util.Mailer;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import io.jsonwebtoken.Jwt;

//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {
	/**
	 * 
	 */
	@Autowired
	JwtProvider jwt;
	@Autowired
	Mailer mail;
	 @Autowired
		@Qualifier("sessionRegistry")
		private SessionRegistry sessionRegistry;
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;
 
    @Autowired
     PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;
    @Autowired
    UserDetailsServiceImpl service;
	@Autowired
	public AuthRestAPIs(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, UserDetailsServiceImpl service) {
		// TODO Auto-generated constructor stub
		this.userRepository=userRepository;
		this.encoder=encoder;
		this.roleRepository=roleRepository;
		this.service=service;
		roleRepository.save(new Role(RoleName.ROLE_ADMIN));
		roleRepository.save(new Role(RoleName.ROLE_DOCTOR));
		roleRepository.save(new Role(RoleName.ROLE_NURSE));
		roleRepository.save(new Role(RoleName.ROLE_RESEARCH));
		roleRepository.save(new Role(RoleName.ROLE_USER));
	 	SignUpForm f=new SignUpForm();
		f.setEmail("arunkumarmn596@gmail.com");
		f.setPassword("nonenone");
		f.setUsername("arun");
		HashSet r=new HashSet();
		r.add("user");
		f.setRoles(r);
		registerUser(f);
		
		SignUpForm f2=new SignUpForm();
		f2.setEmail("admin@gmail.com");
		f2.setPassword("admin123");
		f2.setUsername("admin");
		HashSet r2=new HashSet();
		r2.add("admin");
		f2.setRoles(r2);
		registerUser(f2);
		
		
		 System.out.println("TEST ="+userRepository.findByEmail(f.getEmail()));
	       System.out.println(service.loadUserByUsername(f.getEmail()));
	}

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {
    	System.out.println("Started signin "+loginRequest);
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );
        System.out.println("auth :"+authentication);
        
/*     {
        	"name":"arun kumar",
        	"username":"arun",
        	"email":"arunkumarmn9@gmail.com",
        	"password":"nonenone",
        	"role":["admin"]
        }
*/
        
        
        JsonObject user=((UserPrinciple)authentication.getPrincipal()).getUser().toJson();
        user.addProperty("rememberMe", loginRequest.isRememberMe());
        System.out.println(user.toString());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtProvider.generateJwtToken(user.toString());
   
        		user.addProperty("token", jwt);
        		System.out.println("Ended Signin");
        return ResponseEntity.ok(user.toString());
    }

    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {
    	System.out.println("Started Signup "+signUpRequest);
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity<String>("Fail -> Username is already taken!",
                    HttpStatus.BAD_REQUEST);
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity<String>("Fail -> Email is already in use!",
                    HttpStatus.BAD_REQUEST);
        }
        // Creating user's account
        User user = new User(  signUpRequest.getUsername(),
                signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRoles();
        
        System.out.println(strRoles);
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
        	switch(role) {
	    		case "admin":
	    			Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
	    			roles.add(adminRole);
	    			break;
	    		case "doctor":
	            	Role docRole = roleRepository.findByName(RoleName.ROLE_DOCTOR)
	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
	            	roles.add(docRole);
	            	
	    			break;
	    		case "nurse":
	            	Role nurRole = roleRepository.findByName(RoleName.ROLE_NURSE)
	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
	            	roles.add(nurRole);
	            	
	    			break;
	    		case "research":
	            	Role resRole = roleRepository.findByName(RoleName.ROLE_RESEARCH)
	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
	            	roles.add(resRole);
	            	
	    			break;
	    		default:
	        		Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
	                .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
	        		roles.add(userRole);        			
        	}
        });
        
        user.setRoles(roles);
        userRepository.save(user);
        System.out.println("Ended Signup");
        return ResponseEntity.ok().body("User registered successfully!");
    }
    
    
    @RequestMapping(value = {"/logout"}, method = RequestMethod.POST)
    public String logoutDo(HttpServletRequest request,HttpServletResponse response){
    HttpSession session= request.getSession(false);
    try {
    	
    	System.out.println("hi");
		request.logout();
		 SecurityContextHolder.clearContext();
         session= request.getSession(false);
        if(session != null) {
            session.invalidate();
        
        for(Cookie cookie : (request!=null)?request.getCookies():null) {
            cookie.setMaxAge(0);
        }}
        CookieClearingLogoutHandler cookieClearingLogoutHandler = new CookieClearingLogoutHandler(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY);
        SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
        cookieClearingLogoutHandler.logout(request, response, null);
        securityContextLogoutHandler.logout(request, response, null);
     
	 
			SecurityContext context = SecurityContextHolder.getContext();
			context.setAuthentication(null);

		SecurityContextHolder.clearContext();
		System.out.println(sessionRegistry.getAllPrincipals().stream()
	      .filter(u -> !sessionRegistry.getAllSessions(u, true).isEmpty())
	      .map(name->((UserPrinciple)name).getUsername()	)
	      .collect(Collectors.toList()));
		
		
		sessionRegistry.getAllPrincipals().stream().forEach(sa->{
			 
			sessionRegistry.getAllSessions(sa, true).forEach(si->{
				
				System.out.println(si.getSessionId());
				si.expireNow();
				System.out.println(si.isExpired());
				System.out.println(si.getLastRequest());});
			
		});
		
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		return "Failure";
	}
       

        return "Success";
    }
   
    @RequestMapping("/logoutsuccess")
    public String logoutsuccess() {
    	JsonObject o=new JsonObject();
    	o.addProperty("status", true);
    	o.addProperty("message","success");
    	
    	return o.toString();
    }
    @RequestMapping("/request-password")
    public String requestpassword(@RequestBody String data) {
    	String server_ip="http://192.168.1.35:4200";
    	System.out.println("Request Password");
    	String email=new JsonParser().parse(data).getAsJsonObject().get("email").getAsString();
    	JsonObject o=new JsonObject();
    	o.addProperty("status", true);
    	o.addProperty("message","success");
    	
    	if(userRepository.findByEmail(email)==null) {
        	o.addProperty("status", false);
        	o.addProperty("message","Email does not exist");
        	return o.toString();
    	}
    	Long expiry=Calendar.getInstance().getTimeInMillis()+3600*1000;
    	JsonObject obj=new JsonObject();
    	obj.addProperty("email", email);
    	obj.addProperty("expiry",expiry);
    	String token=jwt.generateJwtToken(obj.toString());
    	try{
    		RequestPassword rp=new RequestPassword();
    		rp.setEmail(email);
    		rp.setToken(token);
    		rp.setExpiredate(expiry+"");
    		System.out.println("Mail MSG: "+mail.sendMail(new String[]{email},server_ip+"/#/auth/reset-password?token="+token,"Reset Password Link"));
    		//reqpass.save(rp);
    	}catch(Exception e) {
        	o.addProperty("status", false);
        	o.addProperty("message","failure");
    	}		
    	return o.toString();
    	 	 	 
    }
    @RequestMapping("/reset-password")
    public String resetPassword(@RequestBody String body) {
    	JsonObject response=new JsonObject();
    	response.addProperty("status", true);
    	response.addProperty("message","success");
    	JsonParser p=new  JsonParser();
    	JsonObject data=(JsonObject) p.parse(body);
    	if(jwtProvider.validateJwtToken(data.get("token").getAsString())){
    		Long expiry=Long.parseLong(jwtProvider.getExpiryFromJwtToken(data.get("token").getAsString()));
    	    //current timestamp						   <token's timestamp
    		if(Calendar.getInstance().getTimeInMillis()<expiry) {
    			User u=userRepository.findByEmail(jwtProvider.getEmailFromJwtToken(data.get("token").getAsString()));
    			u.setPassword(encoder.encode(data.get("password").getAsString()));
    			userRepository.save(u);
    		}
    	}
  
    	 return response.toString();
    }
  
}