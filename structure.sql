
CREATE TABLE servers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port SMALLINT UNSIGNED NOT NULL,
    protocol VARCHAR(8) NOT NULL,
    game_info VARCHAR(255) NOT NULL,
    world_hash VARCHAR(255) NULL,
    description VARCHAR(255) NULL,
    has_advert_groups BOOLEAN DEFAULT 0,
    when_updated TIMESTAMP DEFAULT NOW() ON UPDATE NOW(),
    UNIQUE(host, port)
);

CREATE INDEX idx_servers_protocol ON servers (protocol);
CREATE INDEX idx_servers_when_updated ON servers (when_updated);

CREATE TABLE server_advert_groups (
    server_id BIGINT UNSIGNED,
    group_id MEDIUMINT,
    PRIMARY KEY (server_id, group_id)
);

CREATE INDEX idx_server_advert_groups_server_id ON server_advert_groups (server_id);

CREATE TABLE hosting_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    key_string VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL,
    user_name VARCHAR(255) NOT NULL,
    user_id INT UNSIGNED NOT NULL
);

CREATE INDEX idx_hosting_keys_user_id ON hosting_keys (user_id);

CREATE TABLE auth_tokens (
    user_id INT UNSIGNED NOT NULL,
    token VARCHAR(255) NOT NULL,
    ipv4 INET4 NULL,
    server_host VARCHAR(255) NULL,
    when_created TIMESTAMP DEFAULT NOW(),
    UNIQUE (token)
);

CREATE INDEX idx_auth_tokens_user_id ON auth_tokens (user_id);