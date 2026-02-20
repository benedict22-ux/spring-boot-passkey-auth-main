package com.learnwithiftekhar.passkey.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  /// Password encoder for hashing, will be used to hash passwords before storing them in the database. 
                                             // In this case, we are using BCryptPasswordEncoder, which is a strong hashing algorithm that provides good security for password storage. 
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
                .withUsername("Benedict")
                .password(passwordEncoder()
                        .encode("KingKong123"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(
                        req->
                                req.anyRequest().authenticated()
                ).formLogin(Customizer.withDefaults())
                .webAuthn(
                        webauthn-> webauthn
                                .rpName("Spring Security Relying Party")
                                .rpId("localhost")
                                .allowedOrigins("http://localhost:8080")
                );
        return http.build();
    }
}
