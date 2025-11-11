# Structure du Projet

```
A Vulnerable Web Application/
│
├── 📄 pom.xml                           # Configuration Maven avec dépendances vulnérables
├── 🐳 Dockerfile                        # Image Docker (Tomcat 9 + JDK 11)
├── 🐳 docker-compose.yml                # Orchestration Docker
├── 📝 .dockerignore                     # Fichiers exclus du build Docker
├── 📝 .gitignore                        # Fichiers exclus de Git
│
├── 📚 Documentation
│   ├── README.md                        # Documentation principale complète
│   ├── QUICK-START.md                   # Guide de démarrage rapide (5 min)
│   ├── VULNERABILITIES-SUMMARY.md       # Détail des 10+ vulnérabilités
│   └── CLOUD-DEPLOYMENT.md              # Guide de déploiement AWS/Azure/GCP
│
├── 🔧 Scripts de Déploiement
│   ├── build.sh                         # Compilation Maven automatique
│   └── deploy.sh                        # Déploiement Docker automatique
│
├── 🧪 Tests de Sécurité (security-tests/)
│   ├── test-payloads.md                 # Collection de payloads d'exploitation
│   ├── run-security-scans.sh            # Script de scan automatisé (SAST/DAST/SCA)
│   └── VulnerableApp.postman_collection.json  # Collection Postman pour tests
│
└── 📦 Code Source (src/)
    └── main/
        ├── java/com/vulnerable/app/
        │   │
        │   ├── 🎛️ config/
        │   │   ├── WebConfig.java           # Configuration Spring (vulnérabilités config)
        │   │   └── WebAppInitializer.java   # Initialisation app (logging insuffisant)
        │   │
        │   ├── 🎮 controller/
        │   │   ├── UserController.java      # SQL Injection, XSS, Broken Access Control
        │   │   ├── AuthController.java      # Broken Authentication, JWT faible
        │   │   ├── XmlController.java       # XXE (XML External Entity)
        │   │   ├── FileController.java      # Path Traversal, Command Injection, Upload
        │   │   └── DeserializeController.java # Insecure Deserialization, RCE
        │   │
        │   ├── 📊 model/
        │   │   └── User.java                # Modèle avec données sensibles en clair
        │   │
        │   └── 🔧 service/
        │       ├── UserService.java         # SQL Injection dans les requêtes
        │       └── AuthService.java         # Authentification faible
        │
        ├── resources/
        │   ├── schema.sql                   # Schéma DB avec champs sensibles
        │   └── data.sql                     # Données de test avec mots de passe en clair
        │
        └── webapp/
            ├── index.html                   # Page d'accueil avec documentation
            └── WEB-INF/
                └── web.xml                  # Configuration servlet (cookies non sécurisés)
```

---

## Cartographie des Vulnérabilités par Fichier

### 🔴 Fichiers Critiques

| Fichier | Vulnérabilités | Sévérité |
|---------|---------------|----------|
| **UserService.java** | SQL Injection (LIKE, ORDER BY) | CRITIQUE |
| **DeserializeController.java** | Insecure Deserialization, RCE | CRITIQUE |
| **XmlController.java** | XXE, File Disclosure, SSRF | CRITIQUE |
| **FileController.java** | Command Injection, Path Traversal | CRITIQUE |
| **pom.xml** | Log4Shell, CVEs multiples | CRITIQUE |

### 🟠 Fichiers Haute Sévérité

| Fichier | Vulnérabilités | Sévérité |
|---------|---------------|----------|
| **AuthController.java** | Broken Auth, JWT faible, Session Fixation | HAUTE |
| **UserController.java** | Broken Access Control, XSS, Data Exposure | HAUTE |
| **data.sql** | Mots de passe en clair, données PII | HAUTE |
| **web.xml** | Security Misconfiguration | HAUTE |

### 🟡 Fichiers Moyenne Sévérité

| Fichier | Vulnérabilités | Sévérité |
|---------|---------------|----------|
| **WebConfig.java** | Upload non restreint, pas de CORS | MOYENNE |
| **User.java** | Design non sécurisé | MOYENNE |
| **Dockerfile** | Exécution en root, pas de healthcheck | MOYENNE |

---

## Flux de Données et Points d'Entrée

```
Internet/User
     │
     ▼
┌─────────────────────────────────────────────────┐
│          Tomcat 9 (Port 8080)                   │
│  /vulnerable-app/*                              │
└─────────────────────────────────────────────────┘
     │
     ├─► /auth/*          → AuthController
     │   ├─ /login        → SQL Injection possible
     │   ├─ /register     → Pas de validation
     │   └─ /reset-password → Pas de vérification
     │
     ├─► /user/*          → UserController
     │   ├─ /search       → SQL Injection (LIKE)
     │   ├─ /list         → SQL Injection (ORDER BY)
     │   ├─ /profile/{id} → IDOR
     │   ├─ /comment      → XSS
     │   └─ /admin/export → Data Exposure
     │
     ├─► /file/*          → FileController
     │   ├─ /download     → Path Traversal
     │   ├─ /upload       → Unrestricted Upload
     │   ├─ /read         → Arbitrary File Read
     │   └─ /convert      → Command Injection
     │
     ├─► /xml/*           → XmlController
     │   └─ /parse        → XXE
     │
     └─► /deserialize/*   → DeserializeController
         └─ /object       → Insecure Deserialization
```

---

## Dépendances et Composants Vulnérables

```
pom.xml
  │
  ├─► Spring Framework 5.2.0 (2019)
  │   └─ Multiples CVEs
  │
  ├─► Log4j 2.14.1
  │   └─ CVE-2021-44228 (Log4Shell) ⚠️ CRITIQUE
  │
  ├─► Jackson 2.9.8
  │   └─ CVE-2019-12384 (Désérialisation)
  │
  ├─► Commons FileUpload 1.3.1
  │   └─ CVE-2016-1000031 (DoS)
  │
  ├─► H2 Database 1.4.200
  │   └─ CVE-2021-42392 (RCE)
  │
  └─► JJWT 0.9.0
      └─ Vulnérabilités de signature
```

---

## Cycle de Vie du Déploiement

```
1. Développement
   ├─► Code Java avec vulnérabilités
   └─► Dépendances vulnérables (pom.xml)

2. Compilation
   ├─► mvn clean package
   └─► Génération de vulnerable-app.war

3. Conteneurisation
   ├─► docker build -t vulnerable-web-app
   └─► Image avec Tomcat 9 + JDK 11

4. Déploiement Local
   ├─► docker-compose up -d
   └─► http://localhost:8080/vulnerable-app

5. Déploiement Cloud (optionnel)
   ├─► AWS ECS/Fargate
   ├─► Azure Container Instances
   ├─► Google Cloud Run
   └─► Kubernetes (AKS/EKS/GKE)

6. Tests de Sécurité
   ├─► SAST (SonarQube, Checkmarx)
   ├─► DAST (OWASP ZAP, Burp)
   ├─► SCA (Dependency-Check, Snyk)
   └─► Tests manuels (Postman, curl)
```

---

## Points de Test par Type

### 🔍 SAST (Static Application Security Testing)
```
Fichiers à analyser:
├─ src/main/java/**/*.java    # Tous les contrôleurs et services
├─ pom.xml                     # Analyse des dépendances
└─ src/main/webapp/WEB-INF/*   # Configuration

Outils recommandés:
├─ SonarQube
├─ Checkmarx
├─ Fortify
├─ Semgrep
└─ SpotBugs
```

### 🌐 DAST (Dynamic Application Security Testing)
```
URL cible: http://localhost:8080/vulnerable-app

Endpoints à tester:
├─ /auth/*                     # Authentification
├─ /user/*                     # Gestion utilisateurs
├─ /file/*                     # Gestion fichiers
├─ /xml/*                      # Traitement XML
└─ /deserialize/*              # Désérialisation

Outils recommandés:
├─ OWASP ZAP
├─ Burp Suite
├─ Acunetix
├─ Nikto
└─ sqlmap
```

### 📦 SCA (Software Composition Analysis)
```
Fichier cible: pom.xml

CVEs attendues:
├─ CVE-2021-44228 (Log4Shell)  # CRITIQUE
├─ CVE-2021-42392 (H2 RCE)     # CRITIQUE
├─ CVE-2019-12384 (Jackson)    # HAUTE
└─ Multiples autres CVEs

Outils recommandés:
├─ OWASP Dependency-Check
├─ Snyk
├─ WhiteSource
└─ Black Duck
```

---

## Matrice de Traçabilité

| OWASP Top 10 | Fichier Principal | Endpoint | Méthode Test |
|--------------|-------------------|----------|--------------|
| A01 - Access Control | UserController.java | /user/profile/{id} | curl + IDOR |
| A02 - Crypto Failures | User.java, data.sql | /user/admin/export | curl |
| A03 - Injection | UserService.java | /user/search | sqlmap |
| A04 - Insecure Design | XmlController.java | /xml/parse | curl + payload XXE |
| A05 - Misconfiguration | web.xml, WebConfig.java | Configuration | Revue code |
| A06 - Vulnerable Comp. | pom.xml | N/A | dependency-check |
| A07 - Auth Failures | AuthController.java | /auth/login | curl + bruteforce |
| A08 - Integrity Failures | DeserializeController.java | /deserialize/object | ysoserial |
| A09 - Logging Failures | Toute l'app | N/A | Revue code |
| A10 - SSRF (Bonus) | FileController.java | /file/read | curl + path traversal |

---

## Statistiques du Projet

```
📊 Métriques de Code
├─ Lignes de code Java: ~1,500
├─ Classes: 10
├─ Contrôleurs: 5
├─ Endpoints vulnérables: 15+
├─ Vulnérabilités OWASP: 10+
└─ CVEs de dépendances: 20+

📦 Taille
├─ Code source: ~50 KB
├─ WAR compilé: ~15 MB
├─ Image Docker: ~500 MB
└─ Documentation: ~100 KB

🔒 Vulnérabilités
├─ Critiques: 6
├─ Hautes: 8
├─ Moyennes: 5
└─ Basses: 3+
```

---

## Chemins de Navigation

### Pour un Test Rapide
```
README.md
   └─► QUICK-START.md
        └─► ./deploy.sh
             └─► Tests manuels avec curl
```

### Pour une Étude Complète
```
README.md
   ├─► VULNERABILITIES-SUMMARY.md
   │    └─► Code source correspondant
   │
   └─► security-tests/test-payloads.md
        └─► Collection Postman
```

### Pour un Déploiement Cloud
```
README.md
   └─► CLOUD-DEPLOYMENT.md
        ├─► AWS
        ├─► Azure
        └─► GCP
```

---

## Contacts et Support

- 📖 Documentation complète: [README.md](README.md)
- ⚡ Démarrage rapide: [QUICK-START.md](QUICK-START.md)
- 🔒 Détail vulnérabilités: [VULNERABILITIES-SUMMARY.md](VULNERABILITIES-SUMMARY.md)
- ☁️ Déploiement cloud: [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md)

---

**Note**: Cette structure est optimisée pour faciliter les tests de sécurité et l'apprentissage. Chaque composant est intentionnellement vulnérable pour des raisons pédagogiques.
