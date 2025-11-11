# Guide de Démarrage Rapide

## ⚡ Démarrage en 5 minutes

### Option 1: Docker Compose (Recommandé)

```bash
# 1. Compiler l'application
mvn clean package

# 2. Démarrer l'application
docker-compose up -d

# 3. Accéder à l'application
open http://localhost:8080/vulnerable-app
```

### Option 2: Script de déploiement automatique

```bash
# Tout en une commande
./deploy.sh
```

---

## 📋 Prérequis

### Obligatoires
- **Java 11+** - `java -version`
- **Maven 3.6+** - `mvn -version`
- **Docker** - `docker --version`
- **Docker Compose** - `docker-compose --version`

### Optionnels (pour les tests)
- **OWASP ZAP** - Tests DAST
- **SQLMap** - Tests d'injection SQL
- **Nikto** - Scan de vulnérabilités
- **Burp Suite** - Tests manuels

---

## 🚀 Commandes Essentielles

### Compilation
```bash
# Build complet
mvn clean package

# Build rapide (sans tests)
mvn clean package -DskipTests

# Build avec script
./build.sh
```

### Déploiement

#### Docker Compose
```bash
# Démarrer
docker-compose up -d

# Voir les logs
docker-compose logs -f

# Arrêter
docker-compose down

# Redémarrer
docker-compose restart
```

#### Docker seul
```bash
# Build
docker build -t vulnerable-web-app:latest .

# Run
docker run -d -p 8080:8080 --name vulnerable-app vulnerable-web-app:latest

# Logs
docker logs -f vulnerable-app

# Stop
docker stop vulnerable-app && docker rm vulnerable-app
```

---

## 🧪 Tests Rapides

### Test 1: Vérifier que l'application fonctionne
```bash
curl http://localhost:8080/vulnerable-app
```

**Résultat attendu**: Page HTML d'accueil

### Test 2: SQL Injection
```bash
curl "http://localhost:8080/vulnerable-app/user/search?username=' OR '1'='1"
```

**Résultat attendu**: Liste de tous les utilisateurs

### Test 3: XSS
```bash
curl "http://localhost:8080/vulnerable-app/user/comment?username=test&comment=<script>alert('XSS')</script>"
```

**Résultat attendu**: Script non échappé dans la réponse

### Test 4: Broken Access Control
```bash
# Voir le profil de l'admin sans authentification
curl http://localhost:8080/vulnerable-app/user/profile/1
```

**Résultat attendu**: Profil avec mot de passe et données sensibles

### Test 5: XXE
```bash
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

**Résultat attendu**: Contenu de /etc/passwd (sur Linux/Mac)

---

## 📊 Scans de Sécurité

### Scan rapide avec script
```bash
cd security-tests
./run-security-scans.sh all
```

### OWASP Dependency-Check
```bash
mvn org.owasp:dependency-check-maven:check
```

### SQLMap
```bash
sqlmap -u "http://localhost:8080/vulnerable-app/user/search?username=test" \
       --batch --dbs
```

### OWASP ZAP
```bash
zap-cli quick-scan http://localhost:8080/vulnerable-app
```

---

## 🔍 Endpoints Principaux

### Authentification
- `POST /auth/login` - Connexion
- `POST /auth/register` - Inscription
- `POST /auth/reset-password` - Réinitialisation

### Utilisateurs
- `GET /user/search?username=` - Recherche (SQL Injection)
- `GET /user/list?sortBy=` - Liste (ORDER BY Injection)
- `GET /user/profile/{id}` - Profil (IDOR)
- `GET /user/comment?username=&comment=` - Commentaire (XSS)
- `GET /user/admin/export` - Export (Data Exposure)

### Fichiers
- `GET /file/download?filename=` - Téléchargement (Path Traversal)
- `POST /file/upload` - Upload (Unrestricted)
- `GET /file/read?path=` - Lecture (Arbitrary File Read)
- `GET /file/convert?filename=` - Conversion (Command Injection)

### XML
- `POST /xml/parse` - Parser XML (XXE)

### Désérialisation
- `POST /deserialize/object` - Désérialiser (RCE)
- `GET /deserialize/serialize-example?message=` - Helper

---

## 👥 Comptes de Test

| Username | Password  | Rôle      | Description |
|----------|-----------|-----------|-------------|
| admin    | admin123  | admin     | Administrateur |
| john     | password  | user      | Utilisateur standard |
| alice    | alice2023 | user      | Utilisateur standard |
| bob      | 12345     | user      | Mot de passe faible |
| charlie  | qwerty    | moderator | Modérateur |

---

## 📁 Structure du Projet

```
.
├── src/
│   ├── main/
│   │   ├── java/com/vulnerable/app/
│   │   │   ├── config/          # Configuration Spring
│   │   │   ├── controller/      # Contrôleurs vulnérables
│   │   │   ├── model/           # Modèles
│   │   │   └── service/         # Services
│   │   ├── resources/
│   │   │   ├── schema.sql       # Schéma DB
│   │   │   └── data.sql         # Données de test
│   │   └── webapp/
│   │       └── index.html       # Page d'accueil
├── security-tests/              # Tests de sécurité
│   ├── test-payloads.md         # Payloads de test
│   ├── run-security-scans.sh    # Script de scan
│   └── VulnerableApp.postman_collection.json
├── Dockerfile                   # Image Docker
├── docker-compose.yml           # Orchestration
├── build.sh                     # Script de compilation
├── deploy.sh                    # Script de déploiement
├── README.md                    # Documentation principale
├── VULNERABILITIES-SUMMARY.md   # Détail des vulnérabilités
└── CLOUD-DEPLOYMENT.md          # Déploiement cloud
```

---

## 🛠️ Dépannage

### L'application ne démarre pas

**Problème**: Port 8080 déjà utilisé
```bash
# Trouver le processus
lsof -i :8080

# Changer le port dans docker-compose.yml
ports:
  - "8888:8080"
```

**Problème**: Erreur Maven
```bash
# Nettoyer le cache Maven
mvn clean
rm -rf ~/.m2/repository

# Réessayer
mvn clean package
```

**Problème**: Docker ne démarre pas
```bash
# Vérifier les logs
docker-compose logs

# Reconstruire l'image
docker-compose build --no-cache
```

### L'application est lente

```bash
# Augmenter la mémoire dans docker-compose.yml
environment:
  - JAVA_OPTS=-Xms1g -Xmx2g
```

### Les tests échouent

```bash
# Vérifier que l'application est accessible
curl http://localhost:8080/vulnerable-app

# Attendre le démarrage complet
sleep 30
```

---

## 🎯 Cas d'Usage Typiques

### 1. Tester un outil SAST
```bash
# Pointer votre outil SAST vers le code source
./src/main/java/com/vulnerable/app/

# Résultats attendus: ~50+ vulnérabilités détectées
```

### 2. Tester un outil DAST
```bash
# Démarrer l'application
docker-compose up -d

# Pointer votre scanner vers
http://localhost:8080/vulnerable-app

# Résultats attendus: 10+ vulnérabilités critiques
```

### 3. Tester un outil SCA
```bash
# Scanner le pom.xml
mvn org.owasp:dependency-check-maven:check

# Résultats attendus: Log4Shell, CVE critiques
```

### 4. Formation en sécurité
```bash
# Utiliser les payloads dans security-tests/test-payloads.md
# Importer la collection Postman
# Suivre VULNERABILITIES-SUMMARY.md
```

---

## 📚 Ressources

### Documentation
- [README.md](README.md) - Documentation complète
- [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Détail des vulnérabilités
- [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) - Déploiement cloud
- [security-tests/test-payloads.md](security-tests/test-payloads.md) - Payloads de test

### Collections de Test
- [Postman Collection](security-tests/VulnerableApp.postman_collection.json)
- [Script de Scan](security-tests/run-security-scans.sh)

### Liens Externes
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

## ⚠️ Rappels Importants

1. **NE JAMAIS DÉPLOYER EN PRODUCTION**
2. **Isoler dans un réseau privé**
3. **Utiliser uniquement pour des tests autorisés**
4. **Documenter vos tests**
5. **Nettoyer après les tests**

---

## 🆘 Support

En cas de problème:
1. Vérifier les logs: `docker-compose logs -f`
2. Consulter la documentation complète
3. Vérifier les prérequis
4. Reconstruire depuis zéro: `docker-compose down -v && mvn clean package && docker-compose up --build -d`

---

**Prêt à commencer?**
```bash
./deploy.sh
```

Bonne chance avec vos tests de sécurité! 🔒
