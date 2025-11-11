# Description GitHub

## Description Courte (pour le champ "About")

```
Application Java intentionnellement vulnérable implémentant OWASP Top 10 (2021) pour tester des outils de sécurité applicative (SAST/DAST/SCA). Conteneurisée avec Docker, déployable sur AWS/Azure/GCP.
```

---

## Description README pour GitHub

```markdown
# 🔓 Vulnerable Web Application - OWASP Top 10

[![Java](https://img.shields.io/badge/Java-11+-orange.svg)](https://adoptium.net/)
[![Spring](https://img.shields.io/badge/Spring-5.2.0-green.svg)](https://spring.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red.svg)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

> ⚠️ **ATTENTION**: Cette application contient **intentionnellement** des vulnérabilités de sécurité critiques. Elle est conçue **UNIQUEMENT** pour des tests de sécurité dans des environnements isolés. **NE JAMAIS déployer en production ou exposer publiquement.**

## 📋 Description

Application web Java Spring MVC intentionnellement vulnérable implémentant les **10 principales vulnérabilités du OWASP Top 10 (2021)**, conçue pour tester et valider des outils de sécurité applicative (SAST, DAST, IAST, SCA) et former des équipes à la sécurité.

## ✨ Caractéristiques

### 🎯 Vulnérabilités Implémentées

- ✅ **A01:2021** - Broken Access Control (IDOR, accès non autorisé)
- ✅ **A02:2021** - Cryptographic Failures (données sensibles en clair)
- ✅ **A03:2021** - Injection (SQL Injection, XSS, Command Injection)
- ✅ **A04:2021** - Insecure Design (XXE - XML External Entity)
- ✅ **A05:2021** - Security Misconfiguration (multiples)
- ✅ **A06:2021** - Vulnerable Components (Log4Shell CVE-2021-44228 + 20 CVEs)
- ✅ **A07:2021** - Authentication Failures (auth faible, JWT compromis)
- ✅ **A08:2021** - Data Integrity Failures (désérialisation RCE)
- ✅ **A09:2021** - Security Logging Failures (logging insuffisant)
- ✅ **A10:2021** - SSRF (Path Traversal, File Upload)

### 🛠️ Technologies

- **Langage**: Java 11
- **Framework**: Spring MVC 5.2.0
- **Build**: Maven 3.6+
- **Base de données**: H2 (in-memory)
- **Serveur**: Apache Tomcat 9
- **Conteneurisation**: Docker + Docker Compose

### 📦 Composants Vulnérables

| Composant | Version | CVE | Sévérité |
|-----------|---------|-----|----------|
| Log4j | 2.14.1 | CVE-2021-44228 (Log4Shell) | 🔴 Critique |
| Spring Framework | 5.2.0 | Multiples CVEs | 🔴 Critique |
| H2 Database | 1.4.200 | CVE-2021-42392 | 🔴 Critique |
| Jackson | 2.9.8 | CVE-2019-12384 | 🟠 Haute |
| Commons FileUpload | 1.3.1 | CVE-2016-1000031 | 🟠 Haute |

## 🚀 Démarrage Rapide

### Prérequis

- Java 11+
- Maven 3.6+
- Docker & Docker Compose

### Installation en 3 commandes

```bash
# 1. Cloner le projet
git clone https://github.com/votre-username/vulnerable-web-app.git
cd vulnerable-web-app

# 2. Déployer
./deploy.sh

# 3. Accéder
open http://localhost:8080/vulnerable-app
```

### Tests Rapides

```bash
# SQL Injection
curl "http://localhost:8080/vulnerable-app/user/search?username=' OR '1'='1"

# XSS
curl "http://localhost:8080/vulnerable-app/user/comment?comment=<script>alert('XSS')</script>"

# XXE
curl -X POST http://localhost:8080/vulnerable-app/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

## 📊 Résultats Attendus

### Tests SAST
- **Vulnérabilités**: 50+ détectées
- **Critiques**: 6+
- **Hautes**: 8+

### Tests DAST
- **Vulnérabilités**: 15+ détectées
- **Injection**: SQL, XSS, XXE, Command
- **Broken Access**: IDOR, Auth bypass

### Tests SCA
- **CVEs**: 20+ détectées
- **Log4Shell**: CVE-2021-44228 (CVSS 10.0)
- **Autres critiques**: 5+

## 🎯 Cas d'Usage

### ✅ Idéal pour

- 🔍 **Tester des outils de sécurité**
  - SAST: SonarQube, Checkmarx, Fortify, Semgrep
  - DAST: OWASP ZAP, Burp Suite, Acunetix
  - SCA: OWASP Dependency-Check, Snyk, WhiteSource
  - IAST: Contrast Security, Seeker

- 🎓 **Formation en sécurité**
  - Comprendre OWASP Top 10
  - Pratiquer l'exploitation de vulnérabilités
  - Ateliers de sécurité applicative

- 💼 **Démonstrations**
  - POC pour outils de sécurité
  - Présentation de risques
  - Validation de solutions

### ❌ NE PAS Utiliser Pour

- ❌ Production
- ❌ Environnement public
- ❌ Données réelles
- ❌ Tests non autorisés

## ☁️ Déploiement Cloud

Support complet pour:
- **AWS**: ECS, Fargate, Elastic Beanstalk
- **Azure**: Container Instances, App Service
- **GCP**: Cloud Run, GKE
- **Kubernetes**: Tous providers

⚠️ **Toujours déployer dans un réseau privé isolé avec firewall restrictif.**

## 📚 Documentation

- 📖 [README Complet](README.md) - Documentation détaillée
- ⚡ [Quick Start](QUICK-START.md) - Démarrage en 5 minutes
- 🔒 [Vulnérabilités](VULNERABILITIES-SUMMARY.md) - Détails techniques
- ☁️ [Cloud Deployment](CLOUD-DEPLOYMENT.md) - AWS/Azure/GCP
- 🧪 [Test Payloads](security-tests/test-payloads.md) - 50+ exploits
- 📮 [Postman Collection](security-tests/VulnerableApp.postman_collection.json)

## 📁 Structure du Projet

```
vulnerable-web-app/
├── src/                          # Code source Java
│   ├── controller/               # 5 contrôleurs vulnérables
│   ├── service/                  # Services métier
│   └── model/                    # Modèles de données
├── security-tests/               # Tests et payloads
├── Dockerfile                    # Image Docker
├── docker-compose.yml            # Orchestration
└── docs/                         # 8 guides détaillés
```

## 🔒 Sécurité et Responsabilité

### ⚠️ Avertissement

Cette application est **intentionnellement vulnérable** et **extrêmement dangereuse**.

**Obligations légales**:
- ✅ Utiliser UNIQUEMENT dans un environnement de test isolé
- ✅ Obtenir l'autorisation écrite avant tout test
- ✅ Ne JAMAIS exposer sur Internet public
- ✅ Documenter tous les tests effectués
- ✅ Respecter les lois locales sur la sécurité informatique

### 🛡️ Mesures de Protection

Avant déploiement:
- [ ] Environnement isolé (VPC/VNet)
- [ ] Firewall restrictif (whitelist IP)
- [ ] Pas d'accès Internet public
- [ ] Logging et monitoring activés
- [ ] Auto-delete configuré
- [ ] Équipe de sécurité informée

## 🤝 Contribution

Les contributions sont les bienvenues! Veuillez:
1. Fork le projet
2. Créer une branche (`git checkout -b feature/nouvelle-vuln`)
3. Commit (`git commit -m 'Ajout vulnérabilité XYZ'`)
4. Push (`git push origin feature/nouvelle-vuln`)
5. Ouvrir une Pull Request

## 📝 Licence

Projet éducatif fourni "tel quel" à des fins de test et de formation uniquement.

## 📧 Contact & Support

- 📖 [Documentation](README.md)
- 🐛 [Issues](https://github.com/votre-username/vulnerable-web-app/issues)
- 💬 [Discussions](https://github.com/votre-username/vulnerable-web-app/discussions)

## 🙏 Remerciements

- [OWASP](https://owasp.org/) pour le Top 10
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) pour l'inspiration
- Communauté de la sécurité applicative

## ⭐ Star History

Si ce projet vous est utile, n'oubliez pas de lui donner une étoile! ⭐

---

<div align="center">

**⚠️ Application Intentionnellement Vulnérable - Tests Autorisés Uniquement ⚠️**

Développé pour améliorer la sécurité applicative à travers l'éducation et les tests.

</div>
```

---

## Topics/Tags GitHub

```
owasp
owasp-top-10
security
cybersecurity
vulnerable-application
pentesting
security-testing
appsec
sast
dast
sca
iast
java
spring
spring-mvc
docker
kubernetes
aws
azure
gcp
sql-injection
xss
xxe
log4shell
security-training
vulnerable
intentionally-vulnerable
educational
security-tools
penetration-testing
web-security
application-security
devsecops
```

---

## Social Media Posts

### Twitter/X

```
🔓 Nouveau projet open-source: Application Java intentionnellement vulnérable

✅ OWASP Top 10 (2021) - toutes les vulnérabilités
✅ Log4Shell + 20 CVEs
✅ Docker ready
✅ AWS/Azure/GCP support
✅ Documentation complète

Parfait pour tester vos outils SAST/DAST/SCA!

⚠️ Environnement isolé uniquement

#OWASP #AppSec #DevSecOps #CyberSecurity

https://github.com/votre-username/vulnerable-web-app
```

### LinkedIn

```
🔒 Annonce de Projet Open Source 🔒

Je suis heureux de partager mon nouveau projet: une application Java intentionnellement vulnérable pour tester des outils de sécurité applicative.

🎯 Caractéristiques:
• Implémentation complète OWASP Top 10 (2021)
• 50+ vulnérabilités détectables
• Log4Shell (CVE-2021-44228) inclus
• Support cloud (AWS/Azure/GCP)
• Documentation exhaustive (2000+ lignes)
• Collection Postman incluse

💡 Cas d'usage:
✓ Validation d'outils SAST/DAST/SCA/IAST
✓ Formation équipes de sécurité
✓ Démonstrations POC
✓ Recherche en sécurité

⚠️ Important: Utilisation uniquement dans des environnements isolés pour des tests autorisés.

Parfait pour les équipes DevSecOps, les formateurs en cybersécurité, et les éditeurs d'outils de sécurité!

Lien: https://github.com/votre-username/vulnerable-web-app

#CyberSecurity #AppSec #DevSecOps #OWASP #OpenSource #SecurityTesting
```

---

## Issues Template

### Bug Report
```markdown
**Description du bug**
Description claire et concise du bug.

**Étapes pour reproduire**
1. Aller à '...'
2. Cliquer sur '...'
3. Scroller jusqu'à '...'
4. Voir l'erreur

**Comportement attendu**
Description du comportement attendu.

**Screenshots**
Si applicable, ajouter des captures d'écran.

**Environnement:**
 - OS: [e.g. macOS, Linux, Windows]
 - Java Version: [e.g. 11, 17]
 - Docker Version: [e.g. 20.10]
```

### Feature Request
```markdown
**Quelle vulnérabilité voulez-vous ajouter?**
Description claire de la vulnérabilité.

**Justification**
Pourquoi cette vulnérabilité serait-elle utile?

**OWASP/CWE référence**
Lien vers la documentation OWASP ou CWE.

**Exemple de code**
Si possible, fournir un exemple de code vulnérable.
```

---

## Pull Request Template

```markdown
## Description
Description claire des changements apportés.

## Type de changement
- [ ] Nouvelle vulnérabilité
- [ ] Correction de bug
- [ ] Amélioration de documentation
- [ ] Amélioration de performance
- [ ] Autre (préciser)

## Vulnérabilités ajoutées/modifiées
- [ ] SQL Injection
- [ ] XSS
- [ ] XXE
- [ ] Autre (préciser)

## Checklist
- [ ] Mon code suit le style du projet
- [ ] J'ai commenté les parties vulnérables
- [ ] J'ai mis à jour la documentation
- [ ] J'ai testé mes changements
- [ ] Les vulnérabilités sont exploitables
- [ ] J'ai ajouté des payloads de test

## Tests effectués
Description des tests effectués pour valider les changements.
```

---

Utilisez ces textes pour créer votre dépôt GitHub avec une présentation professionnelle et complète! 🚀
