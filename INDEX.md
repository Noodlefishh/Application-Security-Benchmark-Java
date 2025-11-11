# Index de la Documentation

## 📚 Vue d'Ensemble

Bienvenue dans l'application Java intentionnellement vulnérable! Cette documentation complète vous guidera à travers l'installation, le déploiement et les tests de sécurité.

---

## 🚀 Par Où Commencer?

### Vous voulez démarrer rapidement?
👉 **[QUICK-START.md](QUICK-START.md)** - Démarrage en 5 minutes

### Première installation?
👉 **[INSTALLATION.md](INSTALLATION.md)** - Guide d'installation des prérequis

### Découvrir le projet?
👉 **[README.md](README.md)** - Documentation complète

---

## 📖 Documentation Principale

### 🎯 Guides Essentiels

| Document | Description | Quand l'utiliser |
|----------|-------------|------------------|
| **[README.md](README.md)** | Documentation complète du projet | Première lecture, référence générale |
| **[QUICK-START.md](QUICK-START.md)** | Guide de démarrage rapide (5 min) | Démarrage immédiat |
| **[INSTALLATION.md](INSTALLATION.md)** | Installation des prérequis | Configuration initiale |
| **[VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md)** | Détail des vulnérabilités | Comprendre les failles |
| **[PROJECT-STRUCTURE.md](PROJECT-STRUCTURE.md)** | Structure du projet | Navigation dans le code |
| **[CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md)** | Déploiement cloud | AWS, Azure, GCP |

---

## 🎓 Par Cas d'Usage

### Je veux tester un outil SAST (Analyse Statique)
1. [README.md](README.md) - Section "Tests de Sécurité"
2. [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Voir les vulnérabilités attendues
3. Pointer votre outil vers `src/main/java/`

### Je veux tester un outil DAST (Analyse Dynamique)
1. [QUICK-START.md](QUICK-START.md) - Déployer l'application
2. Pointer votre scanner vers `http://localhost:8080/vulnerable-app`
3. [security-tests/test-payloads.md](security-tests/test-payloads.md) - Payloads de test

### Je veux tester un outil SCA (Analyse de Composition)
1. [QUICK-START.md](QUICK-START.md) - Section "Scans de Sécurité"
2. Scanner le fichier `pom.xml`
3. [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - CVEs attendues

### Je veux former mon équipe à la sécurité
1. [README.md](README.md) - Présentation générale
2. [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Explication détaillée
3. [security-tests/test-payloads.md](security-tests/test-payloads.md) - Exercices pratiques
4. [security-tests/VulnerableApp.postman_collection.json](security-tests/VulnerableApp.postman_collection.json) - Tests Postman

### Je veux déployer sur le cloud
1. [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) - Guide complet
2. Choisir votre plateforme (AWS/Azure/GCP)
3. **Important**: Lire la section "Sécurité et Isolation"

---

## 🔧 Par Type de Tâche

### Installation et Configuration
- [INSTALLATION.md](INSTALLATION.md) - Installation complète
- `./verify-setup.sh` - Vérifier la configuration
- [QUICK-START.md](QUICK-START.md) - Section "Prérequis"

### Compilation et Déploiement
- `./build.sh` - Compiler
- `./deploy.sh` - Déployer
- [QUICK-START.md](QUICK-START.md) - Commandes essentielles
- [README.md](README.md) - Section "Installation et Déploiement"

### Tests et Exploitation
- [security-tests/test-payloads.md](security-tests/test-payloads.md) - Tous les payloads
- [security-tests/VulnerableApp.postman_collection.json](security-tests/VulnerableApp.postman_collection.json) - Collection Postman
- `./security-tests/run-security-scans.sh` - Scans automatisés
- [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Détails techniques

### Déploiement Cloud
- [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) - Guide complet
  - AWS ECS/Fargate
  - Azure Container Instances
  - Google Cloud Run
  - Kubernetes (tous providers)

---

## 🔍 Par Type de Vulnérabilité

### A01:2021 - Broken Access Control
- **Fichier**: [src/main/java/com/vulnerable/app/controller/UserController.java](src/main/java/com/vulnerable/app/controller/UserController.java)
- **Endpoints**: `/user/profile/{id}`, `/user/admin/export`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A01"

### A02:2021 - Cryptographic Failures
- **Fichiers**: [src/main/java/com/vulnerable/app/model/User.java](src/main/java/com/vulnerable/app/model/User.java), [src/main/resources/data.sql](src/main/resources/data.sql)
- **Endpoint**: `/user/admin/export`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A02"

### A03:2021 - Injection (SQL + XSS)
- **Fichier**: [src/main/java/com/vulnerable/app/service/UserService.java](src/main/java/com/vulnerable/app/service/UserService.java)
- **Endpoints**: `/user/search`, `/user/list`, `/user/comment`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A03"
- **Payloads**: [security-tests/test-payloads.md](security-tests/test-payloads.md)

### A04:2021 - Insecure Design (XXE)
- **Fichier**: [src/main/java/com/vulnerable/app/controller/XmlController.java](src/main/java/com/vulnerable/app/controller/XmlController.java)
- **Endpoint**: `/xml/parse`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A04"

### A05:2021 - Security Misconfiguration
- **Fichiers**: [src/main/webapp/WEB-INF/web.xml](src/main/webapp/WEB-INF/web.xml), [src/main/java/com/vulnerable/app/config/WebConfig.java](src/main/java/com/vulnerable/app/config/WebConfig.java)
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A05"

### A06:2021 - Vulnerable Components
- **Fichier**: [pom.xml](pom.xml)
- **CVEs**: Log4Shell (CVE-2021-44228), etc.
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A06"

### A07:2021 - Authentication Failures
- **Fichier**: [src/main/java/com/vulnerable/app/controller/AuthController.java](src/main/java/com/vulnerable/app/controller/AuthController.java)
- **Endpoints**: `/auth/login`, `/auth/register`, `/auth/reset-password`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A07"

### A08:2021 - Data Integrity Failures
- **Fichier**: [src/main/java/com/vulnerable/app/controller/DeserializeController.java](src/main/java/com/vulnerable/app/controller/DeserializeController.java)
- **Endpoint**: `/deserialize/object`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A08"

### A09:2021 - Logging Failures
- **Toute l'application**
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "A09"

### Bonus: Path Traversal, Command Injection
- **Fichier**: [src/main/java/com/vulnerable/app/controller/FileController.java](src/main/java/com/vulnerable/app/controller/FileController.java)
- **Endpoints**: `/file/*`
- **Doc**: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Section "Bonus"

---

## 🧪 Tests de Sécurité

### Documentation des Tests
- [security-tests/test-payloads.md](security-tests/test-payloads.md) - Tous les payloads d'exploitation
- [security-tests/VulnerableApp.postman_collection.json](security-tests/VulnerableApp.postman_collection.json) - Collection Postman
- [QUICK-START.md](QUICK-START.md) - Section "Tests Rapides"

### Scripts Automatisés
- `./security-tests/run-security-scans.sh` - Lance tous les scans
- `./verify-setup.sh` - Vérifie la configuration

### Commandes de Test Rapides
```bash
# Vérifier l'installation
./verify-setup.sh

# Compiler et déployer
./deploy.sh

# Lancer les scans de sécurité
cd security-tests && ./run-security-scans.sh all

# Tests manuels - voir QUICK-START.md
```

---

## 📁 Fichiers Importants

### Configuration
- [pom.xml](pom.xml) - Dépendances Maven (avec CVEs)
- [Dockerfile](Dockerfile) - Image Docker
- [docker-compose.yml](docker-compose.yml) - Orchestration
- [src/main/webapp/WEB-INF/web.xml](src/main/webapp/WEB-INF/web.xml) - Config Servlet

### Code Source Principal
- [src/main/java/com/vulnerable/app/controller/](src/main/java/com/vulnerable/app/controller/) - Tous les contrôleurs
- [src/main/java/com/vulnerable/app/service/](src/main/java/com/vulnerable/app/service/) - Services métier
- [src/main/java/com/vulnerable/app/config/](src/main/java/com/vulnerable/app/config/) - Configuration Spring

### Base de Données
- [src/main/resources/schema.sql](src/main/resources/schema.sql) - Schéma DB
- [src/main/resources/data.sql](src/main/resources/data.sql) - Données de test

### Scripts
- [build.sh](build.sh) - Compilation
- [deploy.sh](deploy.sh) - Déploiement
- [verify-setup.sh](verify-setup.sh) - Vérification
- [security-tests/run-security-scans.sh](security-tests/run-security-scans.sh) - Scans de sécurité

---

## 🌐 Ressources Externes

### OWASP
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### CVE Databases
- [CVE Details](https://www.cvedetails.com/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)

### Outils de Test
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)
- [SQLMap](https://sqlmap.org/)

---

## 🆘 Aide et Support

### Problèmes d'Installation
➡️ [INSTALLATION.md](INSTALLATION.md) - Section "Problèmes Courants"

### Erreurs de Compilation
➡️ [QUICK-START.md](QUICK-START.md) - Section "Dépannage"

### Erreurs de Déploiement
➡️ [README.md](README.md) - Section "Installation et Déploiement"

### Questions sur les Vulnérabilités
➡️ [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Documentation détaillée

### Déploiement Cloud
➡️ [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) - Guides spécifiques

---

## 📊 Navigation Rapide

| Je veux... | Aller à... |
|-----------|-----------|
| Démarrer en 5 minutes | [QUICK-START.md](QUICK-START.md) |
| Installer les prérequis | [INSTALLATION.md](INSTALLATION.md) |
| Comprendre le projet | [README.md](README.md) |
| Voir les vulnérabilités | [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) |
| Comprendre la structure | [PROJECT-STRUCTURE.md](PROJECT-STRUCTURE.md) |
| Déployer sur le cloud | [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) |
| Tester avec des payloads | [security-tests/test-payloads.md](security-tests/test-payloads.md) |
| Utiliser Postman | [security-tests/VulnerableApp.postman_collection.json](security-tests/VulnerableApp.postman_collection.json) |

---

## ⚡ Workflow Recommandé

### Premier Déploiement
1. [INSTALLATION.md](INSTALLATION.md) - Installer les prérequis
2. `./verify-setup.sh` - Vérifier la configuration
3. [QUICK-START.md](QUICK-START.md) - Déployer rapidement
4. Tests basiques - curl ou navigateur

### Tests Approfondis
1. [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md) - Comprendre les vulnérabilités
2. [security-tests/test-payloads.md](security-tests/test-payloads.md) - Choisir les payloads
3. [security-tests/VulnerableApp.postman_collection.json](security-tests/VulnerableApp.postman_collection.json) - Tests Postman
4. `./security-tests/run-security-scans.sh all` - Scans automatisés

### Déploiement Production (Tests)
1. [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) - Choisir la plateforme
2. Section "Sécurité et Isolation" - **CRITIQUE**
3. Déployer dans un environnement isolé
4. Tester avec vos outils

---

## 📝 Checklist Complète

### ✅ Installation
- [ ] Java 11+ installé
- [ ] Maven installé
- [ ] Docker installé
- [ ] Docker Compose installé
- [ ] `./verify-setup.sh` réussi

### ✅ Déploiement
- [ ] `./build.sh` réussi
- [ ] `./deploy.sh` réussi
- [ ] Application accessible sur http://localhost:8080/vulnerable-app
- [ ] Page d'accueil affichée correctement

### ✅ Tests Basiques
- [ ] SQL Injection testé
- [ ] XSS testé
- [ ] XXE testé
- [ ] Broken Access Control testé
- [ ] Path Traversal testé

### ✅ Tests Avancés
- [ ] Collection Postman importée
- [ ] Scans SAST exécutés
- [ ] Scans DAST exécutés
- [ ] Scans SCA exécutés
- [ ] Résultats analysés

---

## 🎯 Objectifs du Projet

Ce projet vous permet de:
- ✅ Tester des outils de sécurité applicative (SAST, DAST, IAST, SCA)
- ✅ Former des équipes à la sécurité applicative
- ✅ Comprendre les vulnérabilités OWASP Top 10
- ✅ Pratiquer l'exploitation de vulnérabilités
- ✅ Évaluer des solutions de sécurité

---

**Prêt à commencer?** → [QUICK-START.md](QUICK-START.md)

**Besoin d'aide?** → Consultez la section appropriée ci-dessus ou le [README.md](README.md) complet.
