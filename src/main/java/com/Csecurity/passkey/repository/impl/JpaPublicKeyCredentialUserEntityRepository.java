package com.Csecurity.passkey.repository.impl;

import com.Csecurity.passkey.domain.User;
import com.Csecurity.passkey.repository.UserRepository;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Repository;

@Repository
public class JpaPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

    private final UserRepository userRepository;

    // FIX 2: Manual constructor (Replaces @RequiredArgsConstructor since Lombok is broken)
    public JpaPublicKeyCredentialUserEntityRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        return userRepository.findByExternalId(id.toBase64UrlString())
                .map(JpaPublicKeyCredentialUserEntityRepository::toPublicKeyCredentialUserEntity)
                .orElse(null);
    }

    @Override
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(JpaPublicKeyCredentialUserEntityRepository::toPublicKeyCredentialUserEntity)
                .orElse(null);
    }

    @Override
    public void save(PublicKeyCredentialUserEntity userEntity) {
        User user = userRepository.findByExternalId(userEntity.getId().toBase64UrlString())
                .orElse(new User());

        user.setExternalId(userEntity.getId().toBase64UrlString());
        user.setUsername(userEntity.getName());
        user.setFullName(userEntity.getDisplayName());
        
        // Ensure your User.java has getPassword() and setPassword()
        if (user.getPassword() == null) {
            user.setPassword("1234");
        }
        userRepository.save(user);
    }

    @Override
    public void delete(Bytes id) {
        userRepository.findByExternalId(id.toBase64UrlString())
                .ifPresent(userRepository::delete);
    }

    private static PublicKeyCredentialUserEntity toPublicKeyCredentialUserEntity(User user) {
        return ImmutablePublicKeyCredentialUserEntity.builder()
                .id(Bytes.fromBase64(user.getExternalId()))
                .name(user.getUsername())
                .displayName(user.getFullName())
                .build();
    }
}