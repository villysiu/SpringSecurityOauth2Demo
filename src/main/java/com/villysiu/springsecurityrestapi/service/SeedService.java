package com.villysiu.springsecurityrestapi.service;

import com.villysiu.springsecurityrestapi.model.ERole;
import com.villysiu.springsecurityrestapi.model.Role;
import com.villysiu.springsecurityrestapi.repository.RoleRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class SeedService {
    private static final Logger logger = LoggerFactory.getLogger(SeedService.class);
    private final RoleRepository roleRepository;
    public SeedService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Transactional
    public void init() {
        for (ERole role : ERole.values()) {
            if (!roleRepository.existsByErole(role)){
                roleRepository.save(new Role(role));
                logger.info("Role {} has been created.", role.name());
            } else {
                logger.info("Role {} already exists.", role.name());
            }
        }
    }
}
