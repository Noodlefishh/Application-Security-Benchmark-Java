-- Schéma de base de données pour l'application vulnérable

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,  -- VULNÉRABILITÉ: Pas de hashing
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    ssn VARCHAR(11),                 -- VULNÉRABILITÉ: Données sensibles
    credit_card VARCHAR(19)          -- VULNÉRABILITÉ: Données sensibles
);

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    -- VULNÉRABILITÉ: Logging insuffisant - pas d'IP, pas de user agent, etc.
);
