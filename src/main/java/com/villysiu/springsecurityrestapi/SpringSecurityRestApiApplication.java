package com.villysiu.springsecurityrestapi;

import com.villysiu.springsecurityrestapi.service.SeedService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableConfigurationProperties()
public class SpringSecurityRestApiApplication {

    private SeedService seedService;
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityRestApiApplication.class, args);
    }
    @Bean
    CommandLineRunner initSeed(SeedService seedService) {
        return args -> {
            seedService.init();
        };

    }
}
