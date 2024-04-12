package com.mysecurity.securityPro.config;


import ch.qos.logback.core.util.TimeUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JWTUtils {

    private String jwtSigningKey = "secret";

    public String extractUsername(String token){
return extractClaim(token,Claims::getSubject);
    }

public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
}
public boolean hasClaim(String token,String claimName){
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
}

    public <T> T extractClaim(String token,
                              Function<Claims,T> claimsResolver){
     final    Claims claims = extractAllClaims(token);
     return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return (Claims) Jwts.parser().setSigningKey(jwtSigningKey);
    }

    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }


    public String generateToken(UserDetails userDetails){
        Map<String , Object> claims = new HashMap<>();
        return createToken(claims,userDetails);
    }


    public String generateToken( UserDetails userDetails,Map<String
            , Object> claims) {
        return createToken(claims,userDetails);
    }
private String createToken(Map<String ,
        Object> claims,UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() ))
                .signWith(SignatureAlgorithm.HS256,jwtSigningKey).compact();
}
public boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) &&
                !isTokenExpired(token);
}


}
