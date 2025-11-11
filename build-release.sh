#!/bin/bash

# ========================================
# Build Script for Release v1.0.0
# Application Security Benchmark
# ========================================

set -e

echo ""
echo "========================================"
echo "  Building Vulnerable Web Application"
echo "  Version: 1.0.0"
echo "========================================"
echo ""

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "[ERROR] Maven is not installed"
    echo "Please install Maven: https://maven.apache.org/download.cgi"
    exit 1
fi

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "[ERROR] Java is not installed"
    echo "Please install Java 11 or higher: https://adoptium.net/"
    exit 1
fi

echo "[INFO] Checking Java version..."
java -version

echo ""
echo "[INFO] Checking Maven version..."
mvn -version

echo ""
echo "========================================"
echo "  Step 1: Cleaning previous builds"
echo "========================================"
echo ""

mvn clean

echo ""
echo "========================================"
echo "  Step 2: Building WAR package"
echo "========================================"
echo ""

mvn package -DskipTests

echo ""
echo "========================================"
echo "  Step 3: Verifying build artifacts"
echo "========================================"
echo ""

if [ -f "target/vulnerable-app.war" ]; then
    echo "[SUCCESS] WAR file created successfully"
    echo "Location: target/vulnerable-app.war"
    ls -lh target/vulnerable-app.war
else
    echo "[ERROR] WAR file not found"
    exit 1
fi

echo ""
echo "========================================"
echo "  Step 4: Creating release directory"
echo "========================================"
echo ""

mkdir -p release/v1.0.0

echo "[INFO] Copying artifacts to release directory..."
cp target/vulnerable-app.war release/v1.0.0/vulnerable-app-1.0.0.war

echo ""
echo "========================================"
echo "  Step 5: Building Docker image"
echo "========================================"
echo ""

if command -v docker &> /dev/null; then
    echo "[INFO] Docker found, building image..."
    docker build -t vulnerable-web-app:1.0.0 .
    echo "[SUCCESS] Docker image created: vulnerable-web-app:1.0.0"

    # Save Docker image as tar
    echo "[INFO] Exporting Docker image..."
    docker save vulnerable-web-app:1.0.0 -o release/v1.0.0/vulnerable-web-app-1.0.0-docker.tar
    echo "[SUCCESS] Docker image exported to: release/v1.0.0/vulnerable-web-app-1.0.0-docker.tar"
else
    echo "[WARNING] Docker not found, skipping Docker image creation"
fi

echo ""
echo "========================================"
echo "  Step 6: Creating checksums"
echo "========================================"
echo ""

cd release/v1.0.0

# Create SHA256 checksums
sha256sum vulnerable-app-1.0.0.war > checksums.txt
echo "[SUCCESS] Checksum created for WAR file"

if [ -f "vulnerable-web-app-1.0.0-docker.tar" ]; then
    sha256sum vulnerable-web-app-1.0.0-docker.tar >> checksums.txt
    echo "[SUCCESS] Checksum created for Docker image"
fi

cd ../..

echo ""
echo "========================================"
echo "  BUILD SUCCESSFUL!"
echo "========================================"
echo ""
echo "Release artifacts created in: release/v1.0.0/"
echo ""
ls -lh release/v1.0.0/
echo ""
echo "Next steps:"
echo "  1. Test the WAR file: copy to Tomcat webapps directory"
echo "  2. Test the Docker image: docker load -i release/v1.0.0/vulnerable-web-app-1.0.0-docker.tar"
echo "  3. Create GitHub release and upload artifacts"
echo ""
