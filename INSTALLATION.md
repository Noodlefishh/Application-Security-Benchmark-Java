# Guide d'Installation

## Vérification de l'Installation

Exécutez le script de vérification:

```bash
./verify-setup.sh
```

Ce script vérifie:
- ✅ Tous les fichiers du projet
- ✅ La structure du code source
- ✅ Les contrôleurs vulnérables
- ✅ Les outils requis (Java, Maven, Docker)
- ⚠️ Les outils optionnels de test

---

## Installation des Prérequis

### macOS

```bash
# Homebrew (si pas déjà installé)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Java 11
brew install openjdk@11
echo 'export PATH="/opt/homebrew/opt/openjdk@11/bin:$PATH"' >> ~/.zshrc

# Maven
brew install maven

# Docker Desktop
brew install --cask docker
# Puis lancer Docker Desktop depuis Applications

# Vérification
java -version
mvn -version
docker --version
docker-compose --version
```

### Linux (Ubuntu/Debian)

```bash
# Java 11
sudo apt update
sudo apt install openjdk-11-jdk -y

# Maven
sudo apt install maven -y

# Docker
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Vérification
java -version
mvn -version
docker --version
docker-compose --version
```

### Windows

**Option 1: WSL2 (Recommandé)**
```powershell
# Installer WSL2
wsl --install

# Puis suivre les instructions Linux ci-dessus dans WSL
```

**Option 2: Installation native**
1. **Java 11**
   - Télécharger: https://adoptium.net/
   - Installer et configurer JAVA_HOME

2. **Maven**
   - Télécharger: https://maven.apache.org/download.cgi
   - Extraire et ajouter bin/ au PATH

3. **Docker Desktop**
   - Télécharger: https://www.docker.com/products/docker-desktop
   - Installer et démarrer

---

## Installation des Outils de Test (Optionnels)

### SQLMap
```bash
# macOS
brew install sqlmap

# Linux
sudo apt install sqlmap

# Ou via pip
pip install sqlmap
```

### OWASP ZAP
```bash
# macOS
brew install --cask owasp-zap

# Linux
wget https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2.12.0_Linux.tar.gz
tar -xvf ZAP_2.12.0_Linux.tar.gz

# ZAP CLI
pip install zapcli
```

### Nikto
```bash
# macOS
brew install nikto

# Linux
sudo apt install nikto
```

### Nmap
```bash
# macOS
brew install nmap

# Linux
sudo apt install nmap
```

### Snyk
```bash
npm install -g snyk
snyk auth
```

### Burp Suite Community Edition
- Télécharger: https://portswigger.net/burp/communitydownload
- Version gratuite avec fonctionnalités essentielles

---

## Vérification Post-Installation

Après installation, vérifiez que tout fonctionne:

```bash
# Java
java -version
# Sortie attendue: openjdk version "11.x.x"

# Maven
mvn -version
# Sortie attendue: Apache Maven 3.6.x ou supérieur

# Docker
docker --version
docker-compose --version
# Sortie attendue: Docker version 20.x.x ou supérieur

# Vérification complète
./verify-setup.sh
```

---

## Configuration de la Mémoire

### Pour Docker Desktop

**macOS/Windows:**
1. Ouvrir Docker Desktop
2. Préférences → Resources
3. Memory: Au moins 4 GB (8 GB recommandé)
4. CPUs: Au moins 2
5. Redémarrer Docker

### Pour Linux
```bash
# Vérifier les ressources disponibles
docker info | grep -i memory
docker info | grep -i cpu
```

### Pour Java/Maven
```bash
# Augmenter la mémoire Maven (optionnel)
export MAVEN_OPTS="-Xmx2048m"
```

---

## Problèmes Courants et Solutions

### Java: "command not found"

**macOS:**
```bash
# Vérifier l'installation
/usr/libexec/java_home -V

# Configurer JAVA_HOME
export JAVA_HOME=$(/usr/libexec/java_home -v 11)
echo 'export JAVA_HOME=$(/usr/libexec/java_home -v 11)' >> ~/.zshrc
```

**Linux:**
```bash
# Vérifier l'installation
update-alternatives --display java

# Configurer JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' >> ~/.bashrc
```

### Maven: "M2_HOME not set"

```bash
# macOS
export M2_HOME=/opt/homebrew/Cellar/maven/3.x.x/libexec

# Linux
export M2_HOME=/usr/share/maven
```

### Docker: "permission denied"

**Linux uniquement:**
```bash
# Ajouter l'utilisateur au groupe docker
sudo usermod -aG docker $USER

# Se déconnecter et reconnecter
# Ou:
newgrp docker
```

### Port 8080 déjà utilisé

```bash
# Trouver le processus
lsof -i :8080

# Tuer le processus
kill -9 PID

# Ou changer le port dans docker-compose.yml
ports:
  - "8888:8080"
```

---

## Configuration IDE (Optionnel)

### IntelliJ IDEA

1. File → Open → Sélectionner le répertoire du projet
2. Maven projects detected → Import
3. Run → Edit Configurations
4. Ajouter "Maven" configuration
5. Command line: `clean package`

### Eclipse

1. File → Import → Maven → Existing Maven Projects
2. Browse → Sélectionner le répertoire
3. Finish
4. Right-click sur le projet → Maven → Update Project

### VS Code

1. Ouvrir le dossier du projet
2. Installer les extensions:
   - Extension Pack for Java
   - Maven for Java
   - Docker
3. Ouvrir le terminal intégré
4. Exécuter: `mvn clean package`

---

## Configuration Git (Optionnel)

```bash
# Initialiser le dépôt (si ce n'est pas déjà fait)
git init

# Ajouter les fichiers
git add .

# Commit initial
git commit -m "Initial commit - Vulnerable Web Application"

# Ajouter un remote (optionnel)
# git remote add origin https://github.com/username/vulnerable-web-app.git
# git push -u origin main
```

**⚠️ IMPORTANT:**
- NE JAMAIS pousser vers un dépôt public sans documentation claire
- Ajouter des warnings dans le README
- Considérer un dépôt privé

---

## Proxy et Firewall

Si vous êtes derrière un proxy d'entreprise:

### Maven
```bash
# Éditer ~/.m2/settings.xml
<settings>
  <proxies>
    <proxy>
      <id>corporate-proxy</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>proxy.company.com</host>
      <port>8080</port>
    </proxy>
  </proxies>
</settings>
```

### Docker
```bash
# Éditer ~/.docker/config.json
{
  "proxies": {
    "default": {
      "httpProxy": "http://proxy.company.com:8080",
      "httpsProxy": "http://proxy.company.com:8080"
    }
  }
}
```

---

## Prochaines Étapes

Une fois l'installation vérifiée:

1. **Tester la configuration**: `./verify-setup.sh`
2. **Compiler**: `./build.sh`
3. **Déployer**: `./deploy.sh`
4. **Accéder**: http://localhost:8080/vulnerable-app
5. **Commencer les tests**: Voir [QUICK-START.md](QUICK-START.md)

---

## Support

En cas de problème:
- Vérifier les logs: `docker-compose logs -f`
- Consulter [README.md](README.md)
- Vérifier [QUICK-START.md](QUICK-START.md)
- Exécuter: `./verify-setup.sh` pour diagnostiquer

---

**Installation réussie?** Passez au [Guide de Démarrage Rapide](QUICK-START.md)!
