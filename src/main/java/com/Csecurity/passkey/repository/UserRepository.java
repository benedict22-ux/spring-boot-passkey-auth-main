package com.csecurity.passkey.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.csecurity.passkey.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByExternalId(String externalId);

    Optional<User> findByUsername(String username);
}
