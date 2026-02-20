package com.learnwithiftekhar.passkey.security;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.Nullable;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;


public class JdbcPublicKeyCredentialUserEntityRepositoryImpl implements PublicKeyCredentialUserEntityRepository {

    private final JdbcOperations jdbc;

    public JdbcPublicKeyCredentialUserEntityRepositoryImpl(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(@Nullable PublicKeyCredentialUserEntity userEntity) {
        if (userEntity == null) return;
        
        int updated = jdbc.update(
            "UPDATE webauthn_user_entity SET username=?, display_name=? WHERE id=?",
            userEntity.getName(), 
            userEntity.getDisplayName(), 
            userEntity.getId().getBytes()
        );
        
        if (updated == 0) {
            jdbc.update(
                "INSERT INTO webauthn_user_entity (id, username, display_name, created_at) VALUES (?,?,?,?)",
                userEntity.getId().getBytes(), 
                userEntity.getName(), 
                userEntity.getDisplayName(),
                Timestamp.from(Instant.now())
            );
        }
    }

    @Override
    @Nullable
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        var list = jdbc.query(
            "SELECT id, username, display_name FROM webauthn_user_entity WHERE id=?",
            rowMapper(), 
            id.getBytes()
        );
        return list.isEmpty() ? null : list.get(0);
    }

    @Override
    @Nullable
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        var list = jdbc.query(
            "SELECT id, username, display_name FROM webauthn_user_entity WHERE username=?",
            rowMapper(), 
            username
        );
        return list.isEmpty() ? null : list.get(0);
    }

    @Override
    public void delete(Bytes id) {
        jdbc.update("DELETE FROM webauthn_user_entity WHERE id=?", id.getBytes());
    }

    private RowMapper<PublicKeyCredentialUserEntity> rowMapper() {
        return (rs, rowNum) -> ImmutablePublicKeyCredentialUserEntity.builder()
                .id(new Bytes(rs.getBytes("id")))
                .name(rs.getString("username"))
                .displayName(rs.getString("display_name"))
                .build();
    }
}