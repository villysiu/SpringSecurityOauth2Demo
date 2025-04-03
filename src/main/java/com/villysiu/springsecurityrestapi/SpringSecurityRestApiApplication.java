package com.villysiu.springsecurityrestapi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityRestApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityRestApiApplication.class, args);
    }
}
