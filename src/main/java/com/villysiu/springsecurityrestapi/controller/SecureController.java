package com.villysiu.springsecurityrestapi.controller;

import com.villysiu.springsecurityrestapi.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/secure")
public class SecureController {

//    private final JwtService jwtService;
//
//    public SecureController(JwtService jwtService) {
//        this.jwtService = jwtService;
//    }

    @GetMapping("/github_login_success")
    public ResponseEntity<?> handleGithubLogin(@AuthenticationPrincipal UserDetails userDetails ) {

        String username = userDetails.getUsername();

        Map<String, String> message = new HashMap<>();
        message.put("message", "Hello " + username + ". You have successfully logged in via GitHub!");
        return new ResponseEntity<>(message, HttpStatus.OK);
    }
    @GetMapping("/secret1")
    public ResponseEntity<String> secret1() {
        return new ResponseEntity<>("{\"message\":  \"You are viewing secret 1!\"}" , HttpStatus.OK);
    }
    @GetMapping("/secret2")
    public ResponseEntity<String> secret2() {
        return new ResponseEntity<>("{\"message\":  \"You are viewing secret 2\"}" , HttpStatus.OK);
    }



}
