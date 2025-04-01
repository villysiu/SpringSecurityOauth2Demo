package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.controller.AuthenticationController;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtService {

    // set in .env
    @Value("${jwt.token.secret}")
    private String secret;

    @Value("${jwt.token.expires}")
    private Long jwtExpiresMinutes;

    private Claims claims;
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    private final HttpServletResponse response;

    public JwtService(HttpServletResponse response) {
        this.response = response;
    }

    public String generateToken(String email){
        /*
            generate token with jwts builder
            subject accepts string
            issued at and expireAt accept a date time object
            signWith accepts a secretKey
         */
        logger.info("Generating JWT token");
        String jwt = Jwts.builder()
                .subject(email) //username here is indeed the email
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiresMinutes * 60 * 1000))
                .signWith(getSignInKey())
                .compact();
        logger.info("Generated JWT token: " + jwt);
        return jwt;




    }

    public void saveJwtToCookie(String jwt){
        logger.info("Saving JWT token to cookie");
        Cookie cookie = new Cookie("JWT", jwt);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(24 * 60 * 60);
        response.addCookie(cookie);
        logger.info("JWT token saved in cookie");
    }
    public String getJwtFromCookie(HttpServletRequest request){
        logger.info("Getting JWT token from cookie");
        Cookie cookie = WebUtils.getCookie(request, "JWT");
        if(cookie != null){
            logger.info("JWT token found in cookie");
            return cookie.getValue();
        }
        logger.info("JWT token not found in cookie");
        return null;

    }
    public void validateToken(String token) throws JwtException {
        logger.info("validating jwt: {}", token);
        try {
            claims = Jwts.parser()
                    .verifyWith(getSignInKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
//            return claims;
            logger.info(" jwt: {} is valid", token);

        } catch(JwtException e){
// catch null, wrong token, expired token
            logger.error(" jwt is invalid: {}", e.getMessage());
            throw new JwtException(e.getMessage());
        }

    }
    public void removeTokenFromCookie(HttpServletResponse response){

        Cookie cookie = new Cookie("JWT", null);
        cookie.setHttpOnly(true);               // Ensure the HttpOnly flag is still set (same as when you created it)
        cookie.setSecure(true);                 // Ensure the Secure flag is still set
        cookie.setPath("/");                    // Set the same path as the original cookie
        cookie.setMaxAge(0);

        response.addCookie(cookie);

    }

    private SecretKey getSignInKey() {
//        SignatureAlgorithm.HS256, this.secret
        byte[] keyBytes = Decoders.BASE64.decode(this.secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractEmail() {
        return claims.getSubject();
    }

}
