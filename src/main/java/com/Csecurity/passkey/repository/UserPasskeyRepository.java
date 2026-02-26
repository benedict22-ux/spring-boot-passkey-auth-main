package com.Csecurity.passkey.repository;

import com.Csecurity.passkey.domain.UserPasskey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface UserPasskeyRepository extends JpaRepository<UserPasskey, Long> {

    Optional<UserPasskey> findByCredentialId(String credentialId);

    @Query("SELECT up FROM UserPasskey up WHERE up.user.externalId = :externalId")
    List<UserPasskey> findByUserExternalId(@Param("externalId") String externalId);
}
