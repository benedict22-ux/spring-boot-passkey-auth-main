
package com.Csecurity.passkey.domain;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "t_user_passkey")
public class UserPasskey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    private String label;
    private String credentialType;
    
    @Column(name = "credential_id", unique = true)
    private String credentialId;
    
    @Column(columnDefinition = "TEXT")
    private String publicKeyCose;
    
    private Long signatureCount;
    private Boolean uvInitialized;
    private String transports;
    private Boolean backEligible;
    private Boolean backupState; 
    
    @Lob
    @Column(name = "attestation_object", columnDefinition = "LONGBLOB")
    private byte[] attestationObject;

    private Instant createDate;
    private Instant lastUseDate;

    // Getters and setters (explicit to avoid Lombok dependency issues)
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }

    public String getCredentialType() { return credentialType; }
    public void setCredentialType(String credentialType) { this.credentialType = credentialType; }

    public String getCredentialId() { return credentialId; }
    public void setCredentialId(String credentialId) { this.credentialId = credentialId; }

    public String getPublicKeyCose() { return publicKeyCose; }
    public void setPublicKeyCose(String publicKeyCose) { this.publicKeyCose = publicKeyCose; }

    public Long getSignatureCount() { return signatureCount; }
    public void setSignatureCount(Long signatureCount) { this.signatureCount = signatureCount; }
    // Overload to accept primitive long
    public void setSignatureCount(long signatureCount) { this.signatureCount = signatureCount; }

    public Boolean getUvInitialized() { return uvInitialized; }
    public void setUvInitialized(Boolean uvInitialized) { this.uvInitialized = uvInitialized; }

    public String getTransports() { return transports; }
    public void setTransports(String transports) { this.transports = transports; }

    public Boolean getBackEligible() { return backEligible; }
    public void setBackEligible(Boolean backEligible) { this.backEligible = backEligible; }

    public Boolean getBackupState() { return backupState; }
    public void setBackupState(Boolean backupState) { this.backupState = backupState; }

    public byte[] getAttestationObject() { return attestationObject; }
    public void setAttestationObject(byte[] attestationObject) { this.attestationObject = attestationObject; }

    public Instant getCreateDate() { return createDate; }
    public void setCreateDate(Instant createDate) { this.createDate = createDate; }

    public Instant getLastUseDate() { return lastUseDate; }
    public void setLastUseDate(Instant lastUseDate) { this.lastUseDate = lastUseDate; }
}
