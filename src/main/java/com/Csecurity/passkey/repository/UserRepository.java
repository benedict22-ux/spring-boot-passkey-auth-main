package com.Csecurity.passkey.repository;

import com.Csecurity.passkey.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByExternalId(String externalId);

    Optional<User> findByUsername(String username);
}
