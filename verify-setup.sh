#!/bin/bash

# Script de vérification de la configuration du projet
# Usage: ./verify-setup.sh

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SUCCESS=0
WARNINGS=0
ERRORS=0

echo "======================================"
echo "Vérification du Projet"
echo "Application Web Vulnérable"
echo "======================================"
echo ""

# Fonction pour vérifier
check() {
    local name=$1
    local command=$2
    local required=$3

    echo -n "Vérification de $name... "

    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}✓${NC}"
        ((SUCCESS++))
        return 0
    else
        if [ "$required" = "required" ]; then
            echo -e "${RED}✗ (REQUIS)${NC}"
            ((ERRORS++))
        else
            echo -e "${YELLOW}⚠ (Optionnel)${NC}"
            ((WARNINGS++))
        fi
        return 1
    fi
}

# Vérifier les fichiers essentiels
echo -e "${BLUE}[1/5] Fichiers du projet${NC}"
echo "─────────────────────────"

check "pom.xml" "test -f pom.xml" "required"
check "Dockerfile" "test -f Dockerfile" "required"
check "docker-compose.yml" "test -f docker-compose.yml" "required"
check "README.md" "test -f README.md" "required"
check "build.sh" "test -f build.sh && test -x build.sh" "required"
check "deploy.sh" "test -f deploy.sh && test -x deploy.sh" "required"

echo ""

# Vérifier les répertoires source
echo -e "${BLUE}[2/5] Structure du code source${NC}"
echo "─────────────────────────────────"

check "Répertoire config" "test -d src/main/java/com/vulnerable/app/config" "required"
check "Répertoire controller" "test -d src/main/java/com/vulnerable/app/controller" "required"
check "Répertoire model" "test -d src/main/java/com/vulnerable/app/model" "required"
check "Répertoire service" "test -d src/main/java/com/vulnerable/app/service" "required"
check "Répertoire resources" "test -d src/main/resources" "required"
check "Répertoire webapp" "test -d src/main/webapp" "required"

echo ""

# Vérifier les contrôleurs
echo -e "${BLUE}[3/5] Contrôleurs vulnérables${NC}"
echo "──────────────────────────────"

check "UserController" "test -f src/main/java/com/vulnerable/app/controller/UserController.java" "required"
check "AuthController" "test -f src/main/java/com/vulnerable/app/controller/AuthController.java" "required"
check "XmlController" "test -f src/main/java/com/vulnerable/app/controller/XmlController.java" "required"
check "FileController" "test -f src/main/java/com/vulnerable/app/controller/FileController.java" "required"
check "DeserializeController" "test -f src/main/java/com/vulnerable/app/controller/DeserializeController.java" "required"

echo ""

# Vérifier les outils requis
echo -e "${BLUE}[4/5] Outils et dépendances${NC}"
echo "───────────────────────────"

check "Java 11+" "command -v java && java -version 2>&1 | grep -q 'version \"1[1-9]'" "required"
check "Maven" "command -v mvn" "required"
check "Docker" "command -v docker" "required"
check "Docker Compose" "command -v docker-compose" "required"
check "curl" "command -v curl" "optional"
check "git" "command -v git" "optional"

echo ""

# Vérifier les outils de test optionnels
echo -e "${BLUE}[5/5] Outils de test de sécurité (optionnels)${NC}"
echo "──────────────────────────────────────────"

check "SQLMap" "command -v sqlmap" "optional"
check "OWASP ZAP CLI" "command -v zap-cli" "optional"
check "Nikto" "command -v nikto" "optional"
check "Nmap" "command -v nmap" "optional"
check "Snyk" "command -v snyk" "optional"

echo ""
echo "======================================"
echo "Résumé"
echo "======================================"
echo ""

echo -e "${GREEN}✓ Réussites: $SUCCESS${NC}"
if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}⚠ Avertissements: $WARNINGS${NC}"
fi
if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}✗ Erreurs: $ERRORS${NC}"
fi

echo ""

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}❌ ÉCHEC: Des composants requis sont manquants${NC}"
    echo ""
    echo "Installez les composants manquants:"
    echo "  - Java 11+: https://adoptium.net/"
    echo "  - Maven: https://maven.apache.org/download.cgi"
    echo "  - Docker: https://docs.docker.com/get-docker/"
    echo "  - Docker Compose: https://docs.docker.com/compose/install/"
    echo ""
    exit 1
else
    echo -e "${GREEN}✅ SUCCÈS: Tous les composants requis sont présents${NC}"
    echo ""

    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}Note: Certains outils optionnels ne sont pas installés.${NC}"
        echo "Ces outils ne sont pas nécessaires pour exécuter l'application,"
        echo "mais sont utiles pour les tests de sécurité avancés."
        echo ""
    fi

    echo "Prochaines étapes:"
    echo "  1. Compiler: ./build.sh"
    echo "  2. Déployer: ./deploy.sh"
    echo "  3. Tester: curl http://localhost:8080/vulnerable-app"
    echo ""
    echo "Ou en une commande: ./deploy.sh"
    echo ""

    # Vérifier si le WAR existe déjà
    if [ -f "target/vulnerable-app.war" ]; then
        echo -e "${GREEN}✓ WAR déjà compilé: target/vulnerable-app.war${NC}"
        echo "  Vous pouvez directement exécuter: docker-compose up -d"
        echo ""
    else
        echo -e "${YELLOW}⚠ WAR non compilé${NC}"
        echo "  Exécutez d'abord: ./build.sh"
        echo ""
    fi

    exit 0
fi
