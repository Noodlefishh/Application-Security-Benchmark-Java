#!/bin/bash

# Script de compilation et build de l'application vulnérable
# Usage: ./build.sh

set -e

echo "======================================"
echo "Build de l'Application Vulnérable"
echo "======================================"
echo ""

# Vérifier que Maven est installé
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven n'est pas installé. Veuillez installer Maven."
    exit 1
fi

echo "✅ Maven détecté: $(mvn --version | head -n 1)"
echo ""

# Nettoyage
echo "🧹 Nettoyage des fichiers précédents..."
mvn clean

# Compilation
echo ""
echo "🔨 Compilation de l'application..."
mvn package -DskipTests

# Vérification
if [ -f "target/vulnerable-app.war" ]; then
    echo ""
    echo "✅ Build réussi!"
    echo "📦 Fichier WAR créé: target/vulnerable-app.war"
    echo ""
    echo "Prochaines étapes:"
    echo "  - Déployer avec Docker: docker-compose up -d"
    echo "  - Ou construire l'image: docker build -t vulnerable-web-app ."
else
    echo ""
    echo "❌ Erreur lors du build"
    exit 1
fi
