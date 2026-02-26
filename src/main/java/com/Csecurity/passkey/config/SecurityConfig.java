package com.Csecurity.passkey.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
           .authorizeHttpRequests(customizer -> customizer
    .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .webAuthn(customizer -> customizer
                .rpName("Spring Security Relying Party")
                .rpId("localhost")
                .allowedOrigins("http://localhost:8080")
            );
        return http.build();
    }
}