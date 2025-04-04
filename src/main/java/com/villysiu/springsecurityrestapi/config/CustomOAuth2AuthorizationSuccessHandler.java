package com.villysiu.springsecurityrestapi.config;

import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import java.util.Map;

public class CustomOAuth2AuthorizationSuccessHandler implements OAuth2AuthorizationSuccessHandler {

//    private static final Logger logger = Logger.getLogger(CustomOAuth2AuthorizationSuccessHandler.class.getName());

//    https://github.com/spring-projects/spring-security/blob/main/oauth2/oauth2-client/src/main/java/org/springframework/security/oauth2/client/web/DefaultOAuth2AuthorizedClientManager.java#L184
    @Override
    public void onAuthorizationSuccess(OAuth2AuthorizedClient authorizedClient, Authentication principal, Map<String, Object> attributes) {
        // Custom logic after successful OAuth2 authorization
        System.out.println("in onAuthorizationSuccess");
        // Example: Log the details of the authorization request
//        logger.info("Authorization Success for Client: " + authorizationRequest.getClientId());
//        logger.info("Authorization Code: " + authorizationResponse.getCode());

        // should bypass save Oauth2user into security context holder but i dont know how...
    }


}
