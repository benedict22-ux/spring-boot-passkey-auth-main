package com.learnwithiftekhar.passkey.config;

import com.learnwithiftekhar.passkey.security.JdbcPublicKeyCredentialUserEntityRepositoryImpl;
import com.learnwithiftekhar.passkey.security.JdbcUserCredentialRepositoryImpl;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JdbcUserDetailsManager userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    // Bean 1: Your custom User Entity Repo
    @Bean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(JdbcOperations jdbc) {
        return new JdbcPublicKeyCredentialUserEntityRepositoryImpl(jdbc);
    }

    // Bean 2: Your custom Credential Repo
    @Bean
    public UserCredentialRepository userCredentialRepository(JdbcOperations jdbc) {
        return new JdbcUserCredentialRepositoryImpl(jdbc);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/dashboard").authenticated()
                .anyRequest().permitAll()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
            .formLogin(Customizer.withDefaults())
            // NOTICE: We do NOT pass the repositories here. 
            // Spring Security 6.4.2 will automatically find the beans above 
            // as long as they are @Beans in the context.
            .webAuthn(webAuthn -> webAuthn
                .rpName("Spring Security Relying Party")
                .rpId("localhost")
                .allowedOrigins("http://localhost:8080")
            );
        return http.build();
    }

    @Bean
    public CommandLineRunner init(JdbcUserDetailsManager users, 
                                 PasswordEncoder encoder, 
                                 PublicKeyCredentialUserEntityRepository passkeyUserRepo) {
        return args -> {
            String username = "Benedict";
            if (!users.userExists(username)) {
                UserDetails user = User.withUsername(username)
                    .password(encoder.encode("KingKong123"))
                    .roles("USER")
                    .build();
                users.createUser(user);

                var userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
                    .id(Bytes.random())
                    .name(username)
                    .displayName("Benedict Mokoena")
                    .build();
                passkeyUserRepo.save(userEntity);
            }
        };
    }
}