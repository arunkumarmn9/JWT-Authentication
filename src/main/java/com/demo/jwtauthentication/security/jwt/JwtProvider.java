package com.demo.jwtauthentication.security.jwt;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.demo.jwtauthentication.security.services.UserPrinciple;
import java.util.Date;



@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${grokonez.app.jwtSecret}")
    private String jwtSecret;

    @Value("${grokonez.app.jwtExpiration}")
    private int jwtExpiration;

    public String generateJwtToken(String payload) {
        return Jwts.builder()
		               // .setSubject((userPrincipal.getUsername()))
		               // .setIssuedAt(new Date())
		                //.setExpiration(new Date((new Date()).getTime() + jwtExpiration*1000))
		                .setPayload(payload)
		                .signWith(SignatureAlgorithm.HS512, jwtSecret)
		                .compact();
    }
    
    public boolean validateJwtToken(String authToken) {
    	System.out.println("Started ValidateToken");
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            System.out.println("Ended ValidateToken");
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }
        
        return false;
    }
    
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
			                .setSigningKey(jwtSecret)
			                .parseClaimsJws(token)
			                .getBody().get("username").toString();
    }
    public String getEmailFromJwtToken(String token) {
    	
        return Jwts.parser()
			                .setSigningKey(jwtSecret)
			                .parseClaimsJws(token)
			                .getBody().get("email").toString();
    }
    public String getExpiryFromJwtToken(String token) {
    	  return Jwts.parser()
	                .setSigningKey(jwtSecret)
	                .parseClaimsJws(token)
	                .getBody().get("expiry").toString();
    }
}