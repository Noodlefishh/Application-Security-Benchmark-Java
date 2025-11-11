#!/bin/bash

# Script pour exécuter différents scans de sécurité
# Usage: ./run-security-scans.sh [sast|dast|sca|all]

set -e

TARGET_URL="http://localhost:8080/vulnerable-app"
REPORT_DIR="./security-reports"

# Couleurs pour l'output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "Scans de Sécurité - Application Vulnérable"
echo "======================================"
echo ""

# Créer le répertoire de rapports
mkdir -p "$REPORT_DIR"

# Fonction pour SAST (Static Application Security Testing)
run_sast() {
    echo -e "${YELLOW}[SAST] Démarrage de l'analyse statique...${NC}"

    # SpotBugs
    if command -v mvn &> /dev/null; then
        echo -e "${GREEN}[SAST] Exécution de SpotBugs...${NC}"
        mvn spotbugs:spotbugs 2>&1 | tee "$REPORT_DIR/spotbugs-report.txt"
        echo -e "${GREEN}[SAST] Rapport SpotBugs: $REPORT_DIR/spotbugs-report.txt${NC}"
    else
        echo -e "${RED}[SAST] Maven non installé, impossible d'exécuter SpotBugs${NC}"
    fi

    # OWASP Dependency-Check
    if command -v mvn &> /dev/null; then
        echo -e "${GREEN}[SAST] Exécution de OWASP Dependency-Check...${NC}"
        mvn org.owasp:dependency-check-maven:check 2>&1 | tee "$REPORT_DIR/dependency-check-report.txt"
        echo -e "${GREEN}[SAST] Rapport Dependency-Check: $REPORT_DIR/dependency-check-report.txt${NC}"
    fi

    echo -e "${GREEN}[SAST] Analyse statique terminée${NC}\n"
}

# Fonction pour SCA (Software Composition Analysis)
run_sca() {
    echo -e "${YELLOW}[SCA] Démarrage de l'analyse des composants...${NC}"

    # OWASP Dependency-Check
    if command -v mvn &> /dev/null; then
        echo -e "${GREEN}[SCA] Analyse des dépendances avec OWASP Dependency-Check...${NC}"
        mvn org.owasp:dependency-check-maven:check \
            -Dformat=ALL \
            -DfailBuildOnCVSS=0 2>&1 | tee "$REPORT_DIR/sca-report.txt"

        if [ -d "target/dependency-check-report.html" ]; then
            cp target/dependency-check-report.html "$REPORT_DIR/"
            echo -e "${GREEN}[SCA] Rapport HTML copié dans $REPORT_DIR/${NC}"
        fi
    else
        echo -e "${RED}[SCA] Maven non installé${NC}"
    fi

    # Snyk (si installé)
    if command -v snyk &> /dev/null; then
        echo -e "${GREEN}[SCA] Analyse avec Snyk...${NC}"
        snyk test --json > "$REPORT_DIR/snyk-report.json" 2>&1 || true
        echo -e "${GREEN}[SCA] Rapport Snyk: $REPORT_DIR/snyk-report.json${NC}"
    fi

    echo -e "${GREEN}[SCA] Analyse des composants terminée${NC}\n"
}

# Fonction pour DAST (Dynamic Application Security Testing)
run_dast() {
    echo -e "${YELLOW}[DAST] Démarrage de l'analyse dynamique...${NC}"

    # Vérifier que l'application est accessible
    echo -e "${GREEN}[DAST] Vérification de l'accès à l'application...${NC}"
    if ! curl -s "$TARGET_URL" > /dev/null; then
        echo -e "${RED}[DAST] Erreur: L'application n'est pas accessible sur $TARGET_URL${NC}"
        echo -e "${RED}[DAST] Démarrez l'application avec: docker-compose up -d${NC}"
        return 1
    fi

    # OWASP ZAP
    if command -v zap-cli &> /dev/null; then
        echo -e "${GREEN}[DAST] Scan avec OWASP ZAP...${NC}"
        zap-cli quick-scan "$TARGET_URL" 2>&1 | tee "$REPORT_DIR/zap-scan.txt"
        echo -e "${GREEN}[DAST] Rapport ZAP: $REPORT_DIR/zap-scan.txt${NC}"
    else
        echo -e "${YELLOW}[DAST] OWASP ZAP CLI non installé${NC}"
    fi

    # Nikto
    if command -v nikto &> /dev/null; then
        echo -e "${GREEN}[DAST] Scan avec Nikto...${NC}"
        nikto -h "$TARGET_URL" -o "$REPORT_DIR/nikto-report.txt" 2>&1
        echo -e "${GREEN}[DAST] Rapport Nikto: $REPORT_DIR/nikto-report.txt${NC}"
    else
        echo -e "${YELLOW}[DAST] Nikto non installé${NC}"
    fi

    # SQLMap
    if command -v sqlmap &> /dev/null; then
        echo -e "${GREEN}[DAST] Test SQL Injection avec SQLMap...${NC}"
        sqlmap -u "$TARGET_URL/user/search?username=test" \
               --batch \
               --level=3 \
               --risk=3 \
               --output-dir="$REPORT_DIR/sqlmap" 2>&1 | tee "$REPORT_DIR/sqlmap-report.txt" || true
        echo -e "${GREEN}[DAST] Rapport SQLMap: $REPORT_DIR/sqlmap-report.txt${NC}"
    else
        echo -e "${YELLOW}[DAST] SQLMap non installé${NC}"
    fi

    echo -e "${GREEN}[DAST] Analyse dynamique terminée${NC}\n"
}

# Fonction pour afficher le résumé
show_summary() {
    echo ""
    echo "======================================"
    echo "Résumé des Scans"
    echo "======================================"
    echo ""
    echo "Rapports générés dans: $REPORT_DIR"
    echo ""

    if [ -d "$REPORT_DIR" ]; then
        echo "Fichiers générés:"
        ls -lh "$REPORT_DIR"
    fi

    echo ""
    echo "Pour analyser les résultats:"
    echo "  - Ouvrez les fichiers HTML dans un navigateur"
    echo "  - Consultez les fichiers .txt pour les détails"
    echo ""
    echo "Vulnérabilités attendues:"
    echo "  ✓ SQL Injection"
    echo "  ✓ XSS"
    echo "  ✓ XXE"
    echo "  ✓ Path Traversal"
    echo "  ✓ Command Injection"
    echo "  ✓ Insecure Deserialization"
    echo "  ✓ Broken Authentication"
    echo "  ✓ Broken Access Control"
    echo "  ✓ Sensitive Data Exposure"
    echo "  ✓ Security Misconfiguration"
    echo "  ✓ Vulnerable Components (Log4Shell, etc.)"
    echo "  ✓ Insufficient Logging"
    echo ""
}

# Parse arguments
case "${1:-all}" in
    sast)
        run_sast
        ;;
    sca)
        run_sca
        ;;
    dast)
        run_dast
        ;;
    all)
        run_sast
        run_sca
        run_dast
        ;;
    *)
        echo "Usage: $0 [sast|dast|sca|all]"
        echo ""
        echo "Options:"
        echo "  sast  - Static Application Security Testing"
        echo "  sca   - Software Composition Analysis"
        echo "  dast  - Dynamic Application Security Testing"
        echo "  all   - Tous les scans (défaut)"
        exit 1
        ;;
esac

show_summary
