-- Spring Security JDBC users/authorities (default schema)
create table if not exists users (
  username varchar(50) not null primary key,
  password varchar(500) not null,
  enabled boolean not null
);

create table if not exists authorities (
  username varchar(50) not null,
  authority varchar(50) not null,
  constraint fk_authorities_users foreign key(username) references users(username),
  constraint ix_auth_username unique (username, authority)
);

-- Passkeys user entity
create table if not exists webauthn_user_entity (
  id           varbinary(255) primary key,
  username     varchar(191) unique not null,
  display_name varchar(255),
  created_at   timestamp not null
);
create unique index if not exists ux_webauthn_user_username on webauthn_user_entity(username);

-- Passkeys credentials
create table if not exists webauthn_credentials (
  credential_id  varbinary(255) primary key,
  user_id        varbinary(255) not null,
  public_key     varbinary(4096) not null,
  signature_count bigint not null,
  created_at     timestamp not null
);
create index if not exists idx_webauthn_user_id on webauthn_credentials(user_id);