package com.villysiu.springsecurityrestapi.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class ResourceController {

    @GetMapping("/")
    public ResponseEntity<String> public_resource(){
        // assuming no existing user

        return new ResponseEntity<>("You are in public area", HttpStatus.OK);
    }

//    @GetMapping("/login")
//    public ResponseEntity<String> login(@AuthenticationPrincipal OAuth2User principal){
//        // assuming no existing user
//        System.out.println(principal);
//        return new ResponseEntity<>("You are in login area", HttpStatus.OK);
//    }


}


