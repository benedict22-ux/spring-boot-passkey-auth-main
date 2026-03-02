-- 1. Create the users table (only if it doesn't exist)
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    external_id VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100),
    full_name VARCHAR(100)
);

-- 2. Create the passkey table (only if it doesn't exist)
CREATE TABLE IF NOT EXISTS t_user_passkey (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    label VARCHAR(100),
    credential_type VARCHAR(50),
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key_cose TEXT,
    signature_count BIGINT,
    uv_initialized BOOLEAN,
    transports VARCHAR(255),
    back_eligible BOOLEAN,
    backup_state BOOLEAN,
    attestation_object LONGBLOB,
    create_date TIMESTAMP,
    last_use_date TIMESTAMP,
    CONSTRAINT fk_passkey_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Create the authorities table (only if it doesn't exist)
CREATE TABLE IF NOT EXISTS authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);