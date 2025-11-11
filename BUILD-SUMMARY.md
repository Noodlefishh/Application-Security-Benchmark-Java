# Build Summary - Release v1.0.0

## 📦 Scripts de Build Créés

J'ai créé les fichiers suivants pour faciliter le build de votre application :

### 1. Scripts de Build Automatiques

#### [build-release.bat](build-release.bat) (Windows)
- Script batch pour Windows
- Vérifie les prérequis (Java, Maven, Docker)
- Compile l'application
- Crée le WAR file
- Build l'image Docker (si disponible)
- Génère les checksums SHA256
- Organise les artifacts dans `release/v1.0.0/`

**Utilisation :**
```batch
build-release.bat
```

#### [build-release.sh](build-release.sh) (Linux/macOS)
- Script bash pour Linux et macOS
- Mêmes fonctionnalités que la version Windows
- Compatible avec tous les systèmes Unix

**Utilisation :**
```bash
chmod +x build-release.sh
./build-release.sh
```

### 2. GitHub Actions Workflow

#### [.github/workflows/release.yml](.github/workflows/release.yml)
- Workflow CI/CD automatique pour GitHub Actions
- Se déclenche automatiquement lors du push d'un tag `v*.*.*`
- Build automatique du WAR et de l'image Docker
- Création automatique de la release GitHub avec artifacts
- Génération des checksums
- Release notes bilingues (FR/EN)

**Utilisation :**
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
# GitHub Actions créera automatiquement la release
```

### 3. Documentation

#### [RELEASE-INSTRUCTIONS.md](RELEASE-INSTRUCTIONS.md)
- Guide complet pour créer la release v1.0.0
- Instructions d'installation des prérequis
- Procédures de build manuelles et automatiques
- Tests des artifacts
- Création de la release GitHub
- Dépannage

## 🚀 Comment Builder la Release v1.0.0

### Méthode 1 : Build Local (Manuel)

**Prérequis :**
- Java 11+ : https://adoptium.net/
- Maven 3.6+ : https://maven.apache.org/download.cgi
- Docker (optionnel) : https://www.docker.com/products/docker-desktop

**Étapes :**

1. **Installer les prérequis** (si pas déjà fait)
   ```bash
   # Vérifier les installations
   java -version
   mvn -version
   docker --version
   ```

2. **Lancer le script de build**

   Windows :
   ```batch
   cd C:\Users\jonat\Documents\Application-Security-Benchmark
   build-release.bat
   ```

   Linux/macOS :
   ```bash
   cd /path/to/Application-Security-Benchmark
   chmod +x build-release.sh
   ./build-release.sh
   ```

3. **Vérifier les artifacts créés**
   ```
   release/v1.0.0/
   ├── vulnerable-app-1.0.0.war              (~15-25 MB)
   ├── vulnerable-web-app-1.0.0-docker.tar   (~200-350 MB)
   └── checksums.txt                         (SHA256)
   ```

### Méthode 2 : Build avec GitHub Actions (Recommandé)

**Avantages :**
- ✅ Build automatique dans un environnement propre
- ✅ Pas besoin d'installer Java/Maven localement
- ✅ Création automatique de la release GitHub
- ✅ Artifacts uploadés automatiquement

**Étapes :**

1. **Commiter les modifications**
   ```bash
   git add .
   git commit -m "Prepare release v1.0.0"
   git push origin main
   ```

2. **Créer et pousser le tag**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0 - Initial Release"
   git push origin v1.0.0
   ```

3. **Attendre la fin du workflow**
   - Aller sur GitHub : `Actions` tab
   - Suivre l'exécution du workflow "Build and Release"
   - La release sera créée automatiquement dans l'onglet "Releases"

4. **Vérifier la release**
   - Aller dans l'onglet "Releases" de votre repo GitHub
   - Vérifier que v1.0.0 est présente avec les artifacts

## 📋 Checklist de Release

### Avant le Build
- [ ] Code testé et fonctionnel
- [ ] Documentation à jour (README.md, VULNERABILITIES-SUMMARY.md)
- [ ] Version dans pom.xml = 1.0.0
- [ ] CHANGELOG.md créé (si applicable)
- [ ] Tous les commits pushés sur GitHub

### Pendant le Build
- [ ] Build Maven réussi
- [ ] WAR file créé (target/vulnerable-app.war)
- [ ] Image Docker buildée (si applicable)
- [ ] Checksums générés

### Après le Build
- [ ] Artifacts testés localement
- [ ] Tag Git créé et pushé
- [ ] Release GitHub créée
- [ ] Artifacts uploadés sur GitHub
- [ ] Release notes complètes (FR + EN)

### Tests Post-Release
- [ ] Télécharger le WAR depuis GitHub
- [ ] Vérifier le checksum SHA256
- [ ] Déployer sur Tomcat local
- [ ] Tester quelques endpoints vulnérables
- [ ] Vérifier l'image Docker (si applicable)

## 🔧 Commandes Rapides

### Build Manuel Rapide
```bash
mvn clean package
```
Résultat : `target/vulnerable-app.war`

### Build Docker Rapide
```bash
docker build -t vulnerable-web-app:1.0.0 .
```

### Tester le WAR
```bash
# Avec Tomcat installé
cp target/vulnerable-app.war $CATALINA_HOME/webapps/
$CATALINA_HOME/bin/catalina.sh run
```

### Tester avec Docker
```bash
docker run -d -p 8080:8080 --name test-app vulnerable-web-app:1.0.0
curl http://localhost:8080/vulnerable-app
docker stop test-app && docker rm test-app
```

## 📊 Structure des Artifacts

```
Application-Security-Benchmark/
├── target/                              # Build Maven
│   └── vulnerable-app.war              # Artifact principal
├── release/                            # Release directory
│   └── v1.0.0/
│       ├── vulnerable-app-1.0.0.war
│       ├── vulnerable-web-app-1.0.0-docker.tar
│       └── checksums.txt
├── build-release.bat                   # Script Windows
├── build-release.sh                    # Script Linux/macOS
├── RELEASE-INSTRUCTIONS.md             # Documentation complète
└── .github/workflows/release.yml       # CI/CD automatique
```

## ⚠️ Dépannage

### Maven pas trouvé
```bash
# Windows : Ajouter au PATH
# Linux/macOS : Installer via package manager
sudo apt install maven      # Ubuntu/Debian
brew install maven          # macOS
```

### Java version incorrecte
```bash
# Installer Java 11+
# Windows : https://adoptium.net/
# Linux : sudo apt install openjdk-11-jdk
# macOS : brew install openjdk@11
```

### Docker non disponible
- Non bloquant pour le build
- Le script créera seulement le WAR file
- L'image Docker est optionnelle

## 🎯 Prochaines Étapes

1. **Installer les prérequis** : Java 11+ et Maven 3.6+
2. **Lancer le build** : Utiliser `build-release.bat` ou `build-release.sh`
3. **Tester les artifacts** : Déployer localement pour vérifier
4. **Créer la release GitHub** : Suivre les instructions dans RELEASE-INSTRUCTIONS.md
5. **Annoncer la release** : Partager avec la communauté

## 📞 Support

En cas de problème :
1. Consulter [RELEASE-INSTRUCTIONS.md](RELEASE-INSTRUCTIONS.md)
2. Vérifier les logs dans `target/`
3. Créer une issue sur GitHub

---

**Note** : Cette application contient intentionnellement des vulnérabilités. Ne jamais déployer en production.

**Build créé le** : 2025-11-11
**Version cible** : 1.0.0
