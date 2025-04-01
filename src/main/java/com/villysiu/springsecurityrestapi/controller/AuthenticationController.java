package com.villysiu.springsecurityrestapi.controller;

import com.villysiu.springsecurityrestapi.Dto.LoginRequest;
import com.villysiu.springsecurityrestapi.Dto.SignupRequest;
import com.villysiu.springsecurityrestapi.config.JwtAuthenticationFilter;
import com.villysiu.springsecurityrestapi.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private final AuthenticationService authenticationService;
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);


    @PostMapping("/signin")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
        try {
            String username = authenticationService.login(loginRequest);

            Map<String, String> message = new HashMap<>();
            message.put("message", "Hello " + username + ". You have successfully logged in with valid credentials!.");
            return new ResponseEntity<>(message, HttpStatus.OK);
        } catch (Exception e) {
            logger.error(e.getMessage());
            Map<String, String> message = new HashMap<>();
            message.put("message", e.getMessage());
            return new ResponseEntity<>(message, HttpStatus.UNAUTHORIZED);
        }

    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest, HttpServletRequest request){
        try {
            authenticationService.registerAccount(signupRequest);
            return new ResponseEntity<>("{\"message\":  \"Account registered!\"}", HttpStatus.CREATED);
        } catch (Exception e) {
            logger.error(e.getMessage());
            Map<String, String> message = new HashMap<>();
            message.put("message", e.getMessage());
            return new ResponseEntity<>(message, HttpStatus.UNAUTHORIZED);
        }

    }
    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        logoutHandler.logout(request, response, authentication);
        authenticationService.logoutUser(response);
        return new ResponseEntity<>("{\"message\":  \"You've been signed out!\"}", HttpStatus.OK);
    }
}
