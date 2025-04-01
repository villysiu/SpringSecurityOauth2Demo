package com.villysiu.springsecurityrestapi.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

//    private final UserService userService;
//
//    public CustomAuthenticationSuccessHandler(UserService userService) {
//        this.userService = userService;
//    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        System.out.println("in CustomAuthenticationSuccessHandler");

        // Get user details from the authentication object
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println(oauth2User);
        // Save or update user in the database
//        userService.saveOrUpdateUser(oauth2User);

        // Redirect to the user's homepage or any other page after login
//        response.sendRedirect("/home");
    }
}
