# Instructions de Build et Release v1.0.0

## Prérequis

### Windows
- **Java 11 ou supérieur** : [Télécharger Adoptium OpenJDK](https://adoptium.net/)
- **Apache Maven 3.6+** : [Télécharger Maven](https://maven.apache.org/download.cgi)
- **Docker Desktop** (optionnel) : [Télécharger Docker](https://www.docker.com/products/docker-desktop)

### Linux/macOS
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-11-jdk maven docker.io

# macOS (avec Homebrew)
brew install openjdk@11 maven docker
```

## Vérification de l'installation

```bash
# Vérifier Java
java -version
# Devrait afficher : openjdk version "11.x.x" ou supérieur

# Vérifier Maven
mvn -version
# Devrait afficher : Apache Maven 3.6.x ou supérieur

# Vérifier Docker (optionnel)
docker --version
```

## Build de la Release v1.0.0

### Option 1 : Utiliser le script automatique (Recommandé)

#### Windows
```batch
cd C:\Users\jonat\Documents\Application-Security-Benchmark
build-release.bat
```

#### Linux/macOS
```bash
cd /path/to/Application-Security-Benchmark
chmod +x build-release.sh
./build-release.sh
```

### Option 2 : Build manuel

#### Étape 1 : Compiler le projet
```bash
mvn clean package
```

Cette commande va :
- Nettoyer les builds précédents
- Compiler le code source Java
- Exécuter les tests (si présents)
- Créer le fichier WAR dans `target/vulnerable-app.war`

#### Étape 2 : Créer le répertoire de release
```bash
mkdir -p release/v1.0.0
cp target/vulnerable-app.war release/v1.0.0/vulnerable-app-1.0.0.war
```

#### Étape 3 : Build Docker (optionnel)
```bash
docker build -t vulnerable-web-app:1.0.0 .
docker save vulnerable-web-app:1.0.0 -o release/v1.0.0/vulnerable-web-app-1.0.0-docker.tar
```

#### Étape 4 : Créer les checksums

**Windows (PowerShell):**
```powershell
cd release/v1.0.0
Get-FileHash vulnerable-app-1.0.0.war -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Out-File -FilePath checksums.txt -Encoding ASCII
```

**Linux/macOS:**
```bash
cd release/v1.0.0
sha256sum vulnerable-app-1.0.0.war > checksums.txt
sha256sum vulnerable-web-app-1.0.0-docker.tar >> checksums.txt
```

## Artifacts de Release

Après un build réussi, vous aurez les fichiers suivants dans `release/v1.0.0/` :

```
release/v1.0.0/
├── vulnerable-app-1.0.0.war                    # Application WAR (environ 15-20 MB)
├── vulnerable-web-app-1.0.0-docker.tar         # Image Docker (environ 200-300 MB)
└── checksums.txt                               # Checksums SHA256
```

## Test des Artifacts

### Test du WAR

#### Avec Tomcat
```bash
# Copier le WAR dans Tomcat
cp release/v1.0.0/vulnerable-app-1.0.0.war /path/to/tomcat/webapps/vulnerable-app.war

# Démarrer Tomcat
/path/to/tomcat/bin/catalina.sh run

# Accéder à l'application
# http://localhost:8080/vulnerable-app
```

### Test de l'image Docker

```bash
# Charger l'image
docker load -i release/v1.0.0/vulnerable-web-app-1.0.0-docker.tar

# Vérifier que l'image est chargée
docker images | grep vulnerable-web-app

# Lancer le conteneur
docker run -d -p 8080:8080 --name vulnerable-app vulnerable-web-app:1.0.0

# Vérifier que le conteneur fonctionne
docker ps

# Tester l'application
curl http://localhost:8080/vulnerable-app

# Arrêter et supprimer le conteneur
docker stop vulnerable-app
docker rm vulnerable-app
```

## Création de la Release GitHub

### Étape 1 : Créer un tag Git

```bash
# S'assurer d'être sur la branche main
git checkout main

# Créer le tag
git tag -a v1.0.0 -m "Release v1.0.0 - Initial Release"

# Pousser le tag vers GitHub
git push origin v1.0.0
```

### Étape 2 : Créer la Release sur GitHub

1. Aller sur GitHub : `https://github.com/votre-utilisateur/Application-Security-Benchmark/releases`
2. Cliquer sur "Draft a new release"
3. Sélectionner le tag `v1.0.0`
4. Titre : `v1.0.0 - Initial Release / Version Initiale`
5. Copier-coller les release notes (voir fichier séparé)
6. Uploader les artifacts :
   - `vulnerable-app-1.0.0.war`
   - `vulnerable-web-app-1.0.0-docker.tar` (si disponible)
   - `checksums.txt`
7. Cocher "Set as the latest release"
8. Publier la release

### Étape 3 : Vérifier les checksums

Les utilisateurs peuvent vérifier l'intégrité des fichiers téléchargés :

**Windows (PowerShell):**
```powershell
Get-FileHash vulnerable-app-1.0.0.war -Algorithm SHA256
# Comparer avec checksums.txt
```

**Linux/macOS:**
```bash
sha256sum -c checksums.txt
```

## Dépannage

### Erreur : "Maven command not found"
- Vérifier que Maven est installé : `mvn -version`
- Ajouter Maven au PATH :
  - Windows : Éditer les variables d'environnement système
  - Linux/macOS : Ajouter à `~/.bashrc` ou `~/.zshrc`

### Erreur : "Java version incompatible"
- Ce projet nécessite Java 11 minimum
- Vérifier : `java -version`
- Installer OpenJDK 11 ou supérieur

### Erreur de build : "Failed to download dependencies"
- Vérifier la connexion Internet
- Vérifier les paramètres du proxy Maven (si applicable)
- Nettoyer le cache Maven : `rm -rf ~/.m2/repository`

### Erreur Docker : "Cannot connect to Docker daemon"
- Vérifier que Docker est démarré
- Windows : Démarrer Docker Desktop
- Linux : `sudo systemctl start docker`

## Checklist avant Release

- [ ] Code compilé sans erreurs
- [ ] Tests passés (si applicable)
- [ ] WAR créé avec succès
- [ ] Image Docker buildée (optionnel)
- [ ] Checksums générés
- [ ] Artifacts testés localement
- [ ] Tag Git créé
- [ ] Release notes préparées
- [ ] Documentation à jour

## Tailles de fichiers attendues

| Fichier | Taille approximative |
|---------|---------------------|
| vulnerable-app-1.0.0.war | 15-25 MB |
| vulnerable-web-app-1.0.0-docker.tar | 200-350 MB |
| checksums.txt | < 1 KB |

## Support

Pour toute question ou problème :
- Créer une issue sur GitHub
- Consulter la documentation OWASP
- Vérifier les logs de build dans `target/`

---

**Note de sécurité** : Cette application contient intentionnellement des vulnérabilités. Ne jamais déployer en production ou exposer sur Internet.
