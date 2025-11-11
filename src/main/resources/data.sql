-- Données de test avec informations sensibles

INSERT INTO users (username, password, email, role, ssn, credit_card) VALUES
('admin', 'admin123', 'admin@vulnerable.com', 'admin', '123-45-6789', '4532-1234-5678-9010'),
('john', 'password', 'john@example.com', 'user', '987-65-4321', '4024-0071-1234-5678'),
('alice', 'alice2023', 'alice@example.com', 'user', '555-12-3456', '5105-1051-0510-5100'),
('bob', '12345', 'bob@example.com', 'user', '111-22-3333', '3782-822463-10005'),
('charlie', 'qwerty', 'charlie@example.com', 'moderator', '222-33-4444', '6011-1111-1111-1117');

-- VULNÉRABILITÉS dans ces données:
-- 1. Mots de passe en clair
-- 2. Mots de passe faibles
-- 3. Données sensibles (SSN, numéros de carte de crédit) stockées sans chiffrement
-- 4. Numéros de carte de crédit valides (test cards)
