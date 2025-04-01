package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.model.Account;
import com.villysiu.springsecurityrestapi.repository.AccountRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    private final AccountRepository accountRepository;
    public CustomUserDetailsService(AccountRepository accountRepository) {

        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        logger.info("check if {} exists", email);
        Account account = accountRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException(email + " not found." ));
        logger.info("loading userDetails for {}", email);
        Set<GrantedAuthority> authorities = account
                .getRoles()
                .stream()
                .map((role) -> new SimpleGrantedAuthority(role.getErole().name()))
                .collect(Collectors.toSet());

        return new org.springframework.security.core.userdetails.User(
                account.getEmail(),
                account.getPassword(),
                authorities
        );
    }
}
