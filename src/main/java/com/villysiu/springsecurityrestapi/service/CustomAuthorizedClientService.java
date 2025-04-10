package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.model.Account;
import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.repository.AccountRepository;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class CustomAuthorizedClientService  implements OAuth2AuthorizedClientService
{

    private static final Logger logger = LoggerFactory.getLogger(CustomAuthorizedClientService.class);
    private final JwtService jwtService;
    private final HttpServletResponse response;
    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    public CustomAuthorizedClientService(JwtService jwtService, HttpServletResponse response, AccountRepository accountRepository, RoleRepository roleRepository) {
        this.jwtService = jwtService;
        this.response = response;
        this.accountRepository = accountRepository;
        this.roleRepository = roleRepository;
    }



//        @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient client, Authentication authentication) {
        logger.info("Persisting authorized client to Account Repository if not already exists");


        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        String nickname = principal.getAttribute("login");
        String email = (String) principal.getAttributes().get("email");

        if (!accountRepository.existsByEmail(email)) {
            logger.info("Account with email {} does not exist", email);
            Account account = new Account(nickname, email,"");
            Role role = roleRepository.findByErole(ERole.ROLE_USER).orElse(null);
            account.setRoles(Collections.singleton(role));
            logger.info("Saving account {}", account);
            accountRepository.save(account);
            logger.info("Saved account {}", account);
        }

        String jwt = jwtService.generateToken(email);
        jwtService.saveJwtToCookie(jwt);

    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

    }

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        return null;
    }

}
