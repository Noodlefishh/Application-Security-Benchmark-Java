# Guide de Déploiement Cloud

⚠️ **AVERTISSEMENT**: Cette application est intentionnellement vulnérable. Déployez-la UNIQUEMENT dans un environnement isolé et sécurisé pour des tests de sécurité.

## Table des matières
- [Amazon Web Services (AWS)](#aws)
- [Microsoft Azure](#azure)
- [Google Cloud Platform (GCP)](#gcp)
- [Kubernetes](#kubernetes)
- [Sécurité et Isolation](#sécurité-et-isolation)

---

## AWS (Amazon Web Services)

### Option 1: AWS Elastic Container Service (ECS)

#### Prérequis
```bash
# Installer AWS CLI
pip install awscli
aws configure
```

#### Étapes de déploiement

1. **Créer un dépôt ECR**
```bash
aws ecr create-repository --repository-name vulnerable-web-app --region us-east-1
```

2. **Authentification Docker vers ECR**
```bash
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
```

3. **Build et push de l'image**
```bash
# Compiler l'application
mvn clean package

# Build l'image
docker build -t vulnerable-web-app:latest .

# Tag pour ECR
docker tag vulnerable-web-app:latest \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest

# Push vers ECR
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest
```

4. **Créer une définition de tâche ECS**
```json
{
  "family": "vulnerable-web-app",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "vulnerable-app",
      "image": "YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "essential": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/vulnerable-web-app",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

5. **Créer le service ECS**
```bash
# Créer le cluster
aws ecs create-cluster --cluster-name vulnerable-app-cluster

# Créer le service
aws ecs create-service \
  --cluster vulnerable-app-cluster \
  --service-name vulnerable-app-service \
  --task-definition vulnerable-web-app \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxxxx],securityGroups=[sg-xxxxx],assignPublicIp=ENABLED}"
```

### Option 2: AWS Elastic Beanstalk

```bash
# Créer un fichier Dockerrun.aws.json
cat > Dockerrun.aws.json <<EOF
{
  "AWSEBDockerrunVersion": "1",
  "Image": {
    "Name": "YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vulnerable-web-app:latest",
    "Update": "true"
  },
  "Ports": [
    {
      "ContainerPort": "8080"
    }
  ]
}
EOF

# Initialiser et déployer
eb init -p docker vulnerable-app
eb create vulnerable-app-env
```

---

## Azure (Microsoft Azure)

### Option 1: Azure Container Instances (ACI)

#### Prérequis
```bash
# Installer Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
```

#### Étapes de déploiement

1. **Créer un groupe de ressources**
```bash
az group create --name vulnerable-app-rg --location eastus
```

2. **Créer un registre de conteneurs Azure**
```bash
az acr create --resource-group vulnerable-app-rg \
  --name vulnerableappacr --sku Basic
```

3. **Build et push de l'image**
```bash
# Compiler
mvn clean package

# Login vers ACR
az acr login --name vulnerableappacr

# Build et push
docker build -t vulnerable-web-app:latest .
docker tag vulnerable-web-app:latest \
  vulnerableappacr.azurecr.io/vulnerable-web-app:latest
docker push vulnerableappacr.azurecr.io/vulnerable-web-app:latest
```

4. **Déployer sur ACI**
```bash
# Obtenir les credentials ACR
ACR_PASSWORD=$(az acr credential show --name vulnerableappacr \
  --query "passwords[0].value" -o tsv)

# Créer le container instance
az container create \
  --resource-group vulnerable-app-rg \
  --name vulnerable-app \
  --image vulnerableappacr.azurecr.io/vulnerable-web-app:latest \
  --registry-login-server vulnerableappacr.azurecr.io \
  --registry-username vulnerableappacr \
  --registry-password $ACR_PASSWORD \
  --dns-name-label vulnerable-app-test \
  --ports 8080 \
  --cpu 1 \
  --memory 2
```

5. **Obtenir l'URL**
```bash
az container show --resource-group vulnerable-app-rg \
  --name vulnerable-app --query ipAddress.fqdn -o tsv
```

### Option 2: Azure App Service

```bash
# Créer un App Service Plan
az appservice plan create --name vulnerable-app-plan \
  --resource-group vulnerable-app-rg \
  --is-linux --sku B1

# Créer une Web App
az webapp create --resource-group vulnerable-app-rg \
  --plan vulnerable-app-plan \
  --name vulnerable-web-app-test \
  --deployment-container-image-name vulnerableappacr.azurecr.io/vulnerable-web-app:latest

# Configurer le port
az webapp config appsettings set --resource-group vulnerable-app-rg \
  --name vulnerable-web-app-test \
  --settings WEBSITES_PORT=8080
```

---

## GCP (Google Cloud Platform)

### Option 1: Google Cloud Run

#### Prérequis
```bash
# Installer gcloud CLI
curl https://sdk.cloud.google.com | bash
gcloud init
```

#### Étapes de déploiement

1. **Configurer le projet**
```bash
PROJECT_ID="your-project-id"
gcloud config set project $PROJECT_ID
```

2. **Activer les APIs nécessaires**
```bash
gcloud services enable \
  containerregistry.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com
```

3. **Build et push avec Cloud Build**
```bash
# Compiler
mvn clean package

# Build et push (Cloud Build fait tout)
gcloud builds submit --tag gcr.io/$PROJECT_ID/vulnerable-web-app
```

4. **Déployer sur Cloud Run**
```bash
gcloud run deploy vulnerable-web-app \
  --image gcr.io/$PROJECT_ID/vulnerable-web-app \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 2Gi \
  --cpu 1
```

5. **Obtenir l'URL**
```bash
gcloud run services describe vulnerable-web-app \
  --platform managed \
  --region us-central1 \
  --format 'value(status.url)'
```

### Option 2: Google Kubernetes Engine (GKE)

```bash
# Créer un cluster
gcloud container clusters create vulnerable-app-cluster \
  --num-nodes=1 \
  --machine-type=n1-standard-2 \
  --region=us-central1

# Obtenir les credentials
gcloud container clusters get-credentials vulnerable-app-cluster \
  --region us-central1

# Déployer (voir section Kubernetes ci-dessous)
kubectl apply -f k8s-deployment.yaml
```

---

## Kubernetes

### Fichiers de déploiement Kubernetes

**k8s-deployment.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-web-app
  labels:
    app: vulnerable-web-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vulnerable-web-app
  template:
    metadata:
      labels:
        app: vulnerable-web-app
    spec:
      containers:
      - name: vulnerable-app
        image: YOUR_REGISTRY/vulnerable-web-app:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            memory: "2Gi"
            cpu: "1000m"
          requests:
            memory: "1Gi"
            cpu: "500m"
        env:
        - name: JAVA_OPTS
          value: "-Xms512m -Xmx1024m"
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-web-app-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  selector:
    app: vulnerable-web-app
```

**Déploiement**
```bash
# Appliquer le déploiement
kubectl apply -f k8s-deployment.yaml

# Vérifier le statut
kubectl get pods
kubectl get services

# Obtenir l'IP externe
kubectl get service vulnerable-web-app-service
```

---

## Sécurité et Isolation

### ⚠️ Mesures de Sécurité OBLIGATOIRES

#### 1. Isolation Réseau

**AWS - Security Groups**
```bash
# Créer un security group restrictif
aws ec2 create-security-group \
  --group-name vulnerable-app-sg \
  --description "Security group pour application vulnérable - TESTS UNIQUEMENT"

# Autoriser uniquement votre IP
YOUR_IP=$(curl -s ifconfig.me)
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp \
  --port 8080 \
  --cidr $YOUR_IP/32
```

**Azure - Network Security Groups**
```bash
# Créer un NSG
az network nsg create \
  --resource-group vulnerable-app-rg \
  --name vulnerable-app-nsg

# Règle pour votre IP uniquement
az network nsg rule create \
  --resource-group vulnerable-app-rg \
  --nsg-name vulnerable-app-nsg \
  --name AllowMyIP \
  --priority 100 \
  --source-address-prefixes $YOUR_IP/32 \
  --destination-port-ranges 8080 \
  --access Allow \
  --protocol Tcp
```

**GCP - Firewall Rules**
```bash
# Créer une règle de pare-feu restrictive
gcloud compute firewall-rules create allow-vulnerable-app \
  --allow tcp:8080 \
  --source-ranges $YOUR_IP/32 \
  --target-tags vulnerable-app
```

#### 2. VPC Privé / Virtual Network

**Déployer dans un réseau privé isolé**
- Utiliser un VPC/VNet dédié
- Pas d'accès Internet direct
- Utiliser un VPN ou bastion host pour l'accès

#### 3. Monitoring et Alertes

**AWS CloudWatch**
```bash
# Créer une alarme pour trafic suspect
aws cloudwatch put-metric-alarm \
  --alarm-name vulnerable-app-high-traffic \
  --alarm-description "Alerte trafic élevé" \
  --metric-name RequestCount \
  --threshold 1000
```

#### 4. Durée de Vie Limitée

**Configurer une suppression automatique**
```bash
# AWS - Tag pour suppression automatique
aws ec2 create-tags --resources i-xxxxx \
  --tags Key=AutoDelete,Value=true Key=TTL,Value=24h

# Azure - Définir une date d'expiration
az resource tag --tags ExpiryDate=$(date -d '+1 day' +%Y-%m-%d) \
  --ids /subscriptions/.../resourceGroups/vulnerable-app-rg
```

#### 5. Authentification et Logging

- Activer tous les logs (CloudTrail, Azure Monitor, Cloud Logging)
- Configurer des alertes pour accès inhabituels
- Utiliser des credentials temporaires

### Checklist de Sécurité Pré-Déploiement

- [ ] Application déployée dans un VPC/VNet isolé
- [ ] Firewall/Security Group configuré pour votre IP uniquement
- [ ] Pas d'accès public Internet
- [ ] Logging activé
- [ ] Alertes de sécurité configurées
- [ ] TTL/Auto-delete configuré
- [ ] Équipe de sécurité informée
- [ ] Documentation du test

### Nettoyage Après Tests

**AWS**
```bash
# Supprimer le service ECS
aws ecs delete-service --cluster vulnerable-app-cluster \
  --service vulnerable-app-service --force

# Supprimer le cluster
aws ecs delete-cluster --cluster vulnerable-app-cluster

# Supprimer les images ECR
aws ecr delete-repository --repository-name vulnerable-web-app --force
```

**Azure**
```bash
# Supprimer tout le groupe de ressources
az group delete --name vulnerable-app-rg --yes --no-wait
```

**GCP**
```bash
# Supprimer le service Cloud Run
gcloud run services delete vulnerable-web-app \
  --platform managed --region us-central1 --quiet

# Supprimer les images
gcloud container images delete gcr.io/$PROJECT_ID/vulnerable-web-app --quiet
```

---

## Support et Questions

Pour des questions sur le déploiement cloud de cette application de test, veuillez consulter:
- Le fichier README.md principal
- La documentation de sécurité de votre plateforme cloud
- Votre équipe de sécurité interne

**Rappel final**: Ne jamais exposer cette application sur Internet public!
