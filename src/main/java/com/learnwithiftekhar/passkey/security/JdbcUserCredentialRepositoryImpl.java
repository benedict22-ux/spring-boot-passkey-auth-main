package com.learnwithiftekhar.passkey.security;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.lang.Nullable;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

@Repository
public class JdbcUserCredentialRepositoryImpl implements UserCredentialRepository {

    private final JdbcOperations jdbc;

    public JdbcUserCredentialRepositoryImpl(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(CredentialRecord record) {
        int updated = jdbc.update(
            "UPDATE webauthn_credentials SET user_id=?, public_key=?, signature_count=? WHERE credential_id=?",
            record.getUserEntityUserId().getBytes(), 
            record.getPublicKey().getBytes(), 
            record.getSignatureCount(),
            record.getCredentialId().getBytes()
        );
        
        if (updated == 0) {
            jdbc.update(
                "INSERT INTO webauthn_credentials (credential_id, user_id, public_key, signature_count, created_at) VALUES (?,?,?,?,?)",
                record.getCredentialId().getBytes(), 
                record.getUserEntityUserId().getBytes(), 
                record.getPublicKey().getBytes(),
                record.getSignatureCount(), 
                Timestamp.from(Instant.now())
            );
        }
    }

    @Override
    @Nullable
    public CredentialRecord findByCredentialId(Bytes credentialId) {
        List<CredentialRecord> list = jdbc.query(
            "SELECT credential_id, user_id, public_key, signature_count FROM webauthn_credentials WHERE credential_id=?",
            rowMapper(),
            credentialId.getBytes()
        );
        return list.isEmpty() ? null : list.get(0);
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        return jdbc.query(
            "SELECT credential_id, user_id, public_key, signature_count FROM webauthn_credentials WHERE user_id=?",
            rowMapper(),
            userId.getBytes()
        );
    }

    @Override
    public void delete(Bytes credentialId) {
        jdbc.update("DELETE FROM webauthn_credentials WHERE credential_id=?",
            credentialId.getBytes());
    }

    private RowMapper<CredentialRecord> rowMapper() {
        return (rs, rowNum) -> ImmutableCredentialRecord.builder()
                .credentialId(new Bytes(rs.getBytes("credential_id")))
                .userEntityUserId(new Bytes(rs.getBytes("user_id")))
                .publicKey(new ImmutablePublicKeyCose(rs.getBytes("public_key")))
                .signatureCount(rs.getLong("signature_count"))
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .build();
    }
}