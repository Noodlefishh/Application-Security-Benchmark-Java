FROM tomcat:9-jdk11

# Informations sur l'image
LABEL maintainer="security-testing"
LABEL description="Application Java vulnérable pour tests de sécurité"
LABEL version="1.0.0"

# VULNÉRABILITÉ: Exécution en tant que root (pas de USER non-privilégié)

# Copier le WAR dans Tomcat
COPY target/vulnerable-app.war /usr/local/tomcat/webapps/

# VULNÉRABILITÉ: Port standard exposé
EXPOSE 8080

# Configuration Tomcat pour afficher les erreurs détaillées
ENV CATALINA_OPTS="-Xms512m -Xmx1024m"

# Créer le répertoire pour les uploads
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads

# VULNÉRABILITÉ: Pas de healthcheck
# VULNÉRABILITÉ: Pas de limitation des ressources

CMD ["catalina.sh", "run"]
