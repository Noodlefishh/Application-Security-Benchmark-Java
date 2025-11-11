#!/bin/bash

# Script de déploiement de l'application vulnérable
# Usage: ./deploy.sh

set -e

echo "======================================"
echo "Déploiement de l'Application Vulnérable"
echo "======================================"
echo ""

# Vérifier que Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé. Veuillez installer Docker."
    exit 1
fi

# Vérifier que docker-compose est installé
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose n'est pas installé. Veuillez installer Docker Compose."
    exit 1
fi

echo "✅ Docker détecté: $(docker --version)"
echo "✅ Docker Compose détecté: $(docker-compose --version)"
echo ""

# Vérifier que le WAR existe
if [ ! -f "target/vulnerable-app.war" ]; then
    echo "⚠️  Le fichier WAR n'existe pas. Compilation en cours..."
    ./build.sh
fi

# Arrêter les conteneurs existants
echo "🛑 Arrêt des conteneurs existants (si présents)..."
docker-compose down 2>/dev/null || true

# Construire et démarrer
echo ""
echo "🔨 Construction de l'image Docker..."
docker-compose build

echo ""
echo "🚀 Démarrage de l'application..."
docker-compose up -d

# Attendre que l'application démarre
echo ""
echo "⏳ Attente du démarrage de l'application..."
sleep 10

# Vérifier que le conteneur est en cours d'exécution
if docker ps | grep -q vulnerable-web-app; then
    echo ""
    echo "✅ Application déployée avec succès!"
    echo ""
    echo "📍 Accès à l'application:"
    echo "   URL: http://localhost:8080/vulnerable-app"
    echo "   Documentation: http://localhost:8080/vulnerable-app/index.html"
    echo ""
    echo "👤 Comptes de test:"
    echo "   Admin: admin / admin123"
    echo "   User:  john / password"
    echo ""
    echo "📊 Voir les logs: docker-compose logs -f"
    echo "🛑 Arrêter: docker-compose down"
else
    echo ""
    echo "❌ Erreur: Le conteneur n'est pas démarré"
    echo "Voir les logs: docker-compose logs"
    exit 1
fi
