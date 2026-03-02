package com.csecurity.passkey.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.csecurity.passkey.domain.User;
import com.csecurity.passkey.repository.UserRepository;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initDatabase(UserRepository repository,
                                   PasswordEncoder passwordEncoder) {
        return args -> {
            // Check if default admin user already exists
            if (repository.findByUsername("admin").isEmpty()) {

                User user = new User();
                user.setUsername("admin");

                // ✅ Encode the password with BCryptPasswordEncoder
                user.setPassword(passwordEncoder.encode("1234"));

                user.setFullName("Default Admin");

                // External ID matches what your Passkey implementation expects
                user.setExternalId("YWRtaW4="); // Base64 for 'admin'

                // Save the user
                repository.save(user);

                System.out.println("Default user created: admin / 1234");
            }
        };
    }
}