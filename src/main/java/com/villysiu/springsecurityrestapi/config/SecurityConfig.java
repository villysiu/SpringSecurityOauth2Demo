package com.villysiu.springsecurityrestapi.config;

import com.villysiu.springsecurityrestapi.service.CustomAuthorizedClientService;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthorizedClientService customAuthorizedClientService;


    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, CustomAuthorizedClientService customAuthorizedClientService) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.customAuthorizedClientService = customAuthorizedClientService;
    }
@Value("${jwt.token.secret}")
private String secret;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests((auth) ->auth
                        .requestMatchers("/secure/**").authenticated()
                        .anyRequest().permitAll()

                )
                // Disable "JSESSIONID" cookies
                .sessionManagement(manager -> manager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .oauth2Login(config -> config
                        .authorizedClientService(this.customAuthorizedClientService)
                        .defaultSuccessUrl("/secure/github_login_success", true)
                )

                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                )
            ;

        return http.build();
    }



    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = Decoders.BASE64.decode(this.secret);
        return NimbusJwtDecoder.withSecretKey(Keys.hmacShaKeyFor(keyBytes)).build();
    }
    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://127.0.0.1:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
//    @Bean
//    public CustomOAuth2AuthorizationSuccessHandler customOAuth2AuthorizationSuccessHandler() {
//        return new CustomOAuth2AuthorizationSuccessHandler();
//    }
}


