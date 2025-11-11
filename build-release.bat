@echo off
REM ========================================
REM Build Script for Release v1.0.0
REM Application Security Benchmark
REM ========================================

echo.
echo ========================================
echo   Building Vulnerable Web Application
echo   Version: 1.0.0
echo ========================================
echo.

REM Check if Maven is installed
where mvn >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Maven is not installed or not in PATH
    echo Please install Maven from: https://maven.apache.org/download.cgi
    echo.
    pause
    exit /b 1
)

REM Check if Java is installed
where java >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Java is not installed or not in PATH
    echo Please install Java 11 or higher from: https://adoptium.net/
    echo.
    pause
    exit /b 1
)

echo [INFO] Checking Java version...
java -version

echo.
echo [INFO] Checking Maven version...
mvn -version

echo.
echo ========================================
echo   Step 1: Cleaning previous builds
echo ========================================
echo.

call mvn clean
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Clean failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Step 2: Building WAR package
echo ========================================
echo.

call mvn package -DskipTests
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Step 3: Verifying build artifacts
echo ========================================
echo.

if exist "target\vulnerable-app.war" (
    echo [SUCCESS] WAR file created successfully
    echo Location: target\vulnerable-app.war

    REM Get file size
    for %%A in ("target\vulnerable-app.war") do (
        echo Size: %%~zA bytes
    )
) else (
    echo [ERROR] WAR file not found
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Step 4: Creating release directory
echo ========================================
echo.

if not exist "release" mkdir release
if not exist "release\v1.0.0" mkdir release\v1.0.0

echo [INFO] Copying artifacts to release directory...
copy "target\vulnerable-app.war" "release\v1.0.0\vulnerable-app-1.0.0.war"

echo.
echo ========================================
echo   Step 5: Building Docker image
echo ========================================
echo.

where docker >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Docker found, building image...
    docker build -t vulnerable-web-app:1.0.0 .
    if %ERRORLEVEL% EQU 0 (
        echo [SUCCESS] Docker image created: vulnerable-web-app:1.0.0

        REM Save Docker image as tar
        echo [INFO] Exporting Docker image...
        docker save vulnerable-web-app:1.0.0 -o release\v1.0.0\vulnerable-web-app-1.0.0-docker.tar
        echo [SUCCESS] Docker image exported to: release\v1.0.0\vulnerable-web-app-1.0.0-docker.tar
    ) else (
        echo [WARNING] Docker build failed
    )
) else (
    echo [WARNING] Docker not found, skipping Docker image creation
)

echo.
echo ========================================
echo   Step 6: Creating checksums
echo ========================================
echo.

cd release\v1.0.0

REM Create SHA256 checksums using PowerShell
powershell -Command "Get-FileHash vulnerable-app-1.0.0.war -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Out-File -FilePath checksums.txt -Encoding ASCII"
echo [SUCCESS] Checksum created for WAR file

if exist "vulnerable-web-app-1.0.0-docker.tar" (
    powershell -Command "Get-FileHash vulnerable-web-app-1.0.0-docker.tar -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Out-File -FilePath checksums-docker.txt -Encoding ASCII"
    echo [SUCCESS] Checksum created for Docker image
)

cd ..\..

echo.
echo ========================================
echo   BUILD SUCCESSFUL!
echo ========================================
echo.
echo Release artifacts created in: release\v1.0.0\
echo.
dir release\v1.0.0
echo.
echo Next steps:
echo   1. Test the WAR file: copy to Tomcat webapps directory
echo   2. Test the Docker image: docker load -i release\v1.0.0\vulnerable-web-app-1.0.0-docker.tar
echo   3. Create GitHub release and upload artifacts
echo.
pause
