#  Maven  CICD DevSecOps OWASP ZAPROXY — Setup Guide


## For more projects, check out  
[https://harishnshetty.github.io/projects.html](https://harishnshetty.github.io/projects.html)

[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/6135e01f68ebd6c691f8fc2304cfcb6d1e867dd6/ecr1.jpg)](https://youtu.be/KwKtMHBQXk4)

## OWASP ZAPROXY

[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/6135e01f68ebd6c691f8fc2304cfcb6d1e867dd6/ecr2.jpg)](https://youtu.be/KwKtMHBQXk4)

## Jenkins Setup
- Instance Type :- c5.xlarge  [4 Cpu 8Gb Ram ] 
- 30 GB EBS
- This guide assumes an Ubuntu/Debian-like environment and sudo privileges.

---

## Ports to Enable in Security Group

- Jenkins Security Group

| Service         | Port  |
|-----------------|-------|
| HTTP            | 80    |
| HTTPS           | 443   |
| SSH             | 22    | 
| Jenkins         |       |
| SonarQube       |       |
| Prometheus      |       |
| grafana         |       |
| node_exporter   |       |

- Nexus Artifact Security Group

| Service         | Port  |
|-----------------|-------|
| SSH             | 22    | 
| Nexus           | 8081  |
| node_exporter   |       |

## System Update & Common Packages

```bash
sudo apt update
sudo apt upgrade -y

# Common tools
sudo apt install -y bash-completion wget git zip unzip curl jq net-tools build-essential ca-certificates apt-transport-https gnupg fontconfig
```
Reload bash completion if needed:
```bash
source /etc/bash_completion
```

**Install latest Git:**
```bash
sudo add-apt-repository ppa:git-core/ppa
sudo apt update
sudo apt install git -y
```

---

## Java

Install OpenJDK (choose 17 or 21 depending on your needs):

```bash
# OpenJDK 17
sudo apt install -y openjdk-17-jdk

# OR OpenJDK 21
sudo apt install -y openjdk-21-jdk
```
Verify:
```bash
java --version
```

---

## Jenkins

Official docs: https://www.jenkins.io/doc/book/installing/linux/

```bash
sudo wget -O /etc/apt/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
echo "deb [signed-by=/etc/apt/keyrings/jenkins-keyring.asc]" \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null

sudo apt update
sudo apt install -y jenkins
sudo systemctl enable --now jenkins
sudo systemctl start jenkins
sudo systemctl status jenkins
```
Initial admin password:
```bash
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```
Then open: http://your-server-ip:8080

**Note:** Jenkins requires a compatible Java runtime. Check the Jenkins documentation for supported Java versions.

---

## Docker

Official docs: https://docs.docker.com/engine/install/ubuntu/

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group (log out / in or newgrp to apply)
sudo usermod -aG docker $USER
newgrp docker
docker ps
```
If Jenkins needs Docker access:
```bash
sudo usermod -aG docker jenkins
sudo systemctl restart jenkins
```
Check Docker status:
```bash
sudo systemctl status docker
```

---

## Trivy (Vulnerability Scanner)

Docs: https://trivy.dev/v0.65/getting-started/installation/

```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy


trivy --version
```

---

## Prometheus

Official downloads: https://prometheus.io/download/

**Generic install steps:**
```bash
# Create a prometheus user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin prometheus

wget -O prometheus.tar.gz "https://github.com/prometheus/prometheus/releases/download/v3.5.0/prometheus-3.5.0.linux-amd64.tar.gz"
tar -xvf prometheus.tar.gz
cd prometheus-*/

sudo mkdir -p /data /etc/prometheus
sudo mv prometheus promtool /usr/local/bin/
sudo mv consoles/ console_libraries/ /etc/prometheus/
sudo mv prometheus.yml /etc/prometheus/prometheus.yml

sudo chown -R prometheus:prometheus /etc/prometheus /data
```

**Systemd service** (`/etc/systemd/system/prometheus.service`):

```ini
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/data \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090

[Install]
WantedBy=multi-user.target
```

**Enable & start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prometheus
sudo systemctl start prometheus
sudo systemctl status prometheus
```
Access: http://ip-address:9090

---

## Node Exporter [ Setup on the Both instance ]

Docs: https://prometheus.io/docs/guides/node-exporter/

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin node_exporter

wget -O node_exporter.tar.gz "https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz"
tar -xvf node_exporter.tar.gz
sudo mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter*
```
**Systemd service:** (`/etc/systemd/system/node_exporter.service`)
```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
ExecStart=/usr/local/bin/node_exporter --collector.logind

[Install]
WantedBy=multi-user.target
```
Enable & start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
sudo systemctl start node_exporter
sudo systemctl status node_exporter
```
---

**Prometheus scrape config:**

Add to `/etc/prometheus/prometheus.yml`:
```yaml
  - job_name: "node_exporter"
    static_configs:
      - targets:
          - "<host-ip>:9100"
          - "<host-ip>:9100"

  - job_name: "jenkins"
    metrics_path: /prometheus
    static_configs:
      - targets: ["<jenkins-ip>:8080"]
```
Validate config:
```bash
promtool check config /etc/prometheus/prometheus.yml
sudo systemctl restart prometheus
```

---

## Grafana

Docs: https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/

```bash
sudo apt-get install -y apt-transport-https software-properties-common wget

sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list

sudo apt-get update
sudo apt-get install -y grafana

sudo systemctl daemon-reload
sudo systemctl enable --now grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server
```
Access: http://ip-address:3000

---

Datasource: http://promethues-ip:9090

## Dashboard id 
  - Node_Exporter 1860
Docs: https://grafana.com/grafana/dashboards/1860-node-exporter-full/
  - jenkins       9964

---

## nexus Setup in the another machine to Store Artifact
- Docs: https://help.sonatype.com/en/sonatype-nexus-repository.html
- Docs: https://help.sonatype.com/en/download.html

- Instance Type :- t3.medium [2 Cpu 4Gb Ram ] 
- This guide assumes an Ubuntu/Debian-like environment and sudo privileges.

## Replace the link if you need the latest nexus

```bash
#!/bin/bash

# Update package list
sudo apt-get update

# Install Java 17 and wget
sudo apt-get install -y wget apt-transport-https

# Add Corretto repository and install Java 17
sudo apt-get install -y software-properties-common


sudo apt-get update
sudo apt-get install -y openjdk-17-jdk

# Create directories
sudo mkdir -p /opt/nexus/
sudo mkdir -p /tmp/nexus/
cd /tmp/nexus/

# Download and extract Nexus
NEXUSURL="https://download.sonatype.com/nexus/3/nexus-3.85.0-03-linux-x86_64.tar.gz"
sudo wget $NEXUSURL -O nexus.tar.gz
sleep 10
EXTOUT=$(sudo tar xzvf nexus.tar.gz)
NEXUSDIR=$(echo $EXTOUT | cut -d '/' -f1)
sleep 5
sudo rm -rf /tmp/nexus/nexus.tar.gz
sudo cp -r /tmp/nexus/* /opt/nexus/
sleep 5

# Create nexus user and set permissions
sudo useradd --system --no-create-home --shell /bin/false nexus
sudo chown -R nexus:nexus /opt/nexus

# Create systemd service file
sudo cat <<EOT>> /etc/systemd/system/nexus.service
[Unit]
Description=nexus service
After=network.target

[Service]
Type=forking
LimitNOFILE=65536
ExecStart=/opt/nexus/$NEXUSDIR/bin/nexus start
ExecStop=/opt/nexus/$NEXUSDIR/bin/nexus stop
User=nexus
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOT

# Configure Nexus to run as nexus user
sudo echo 'run_as_user="nexus"' > /opt/nexus/$NEXUSDIR/bin/nexus.rc

# Reload systemd and start Nexus
sudo systemctl daemon-reload
sudo systemctl start nexus
sudo systemctl enable nexus

# Clean up
sudo rm -rf /tmp/nexus/

echo "Nexus installation completed!"
echo "Check status with: sudo systemctl status nexus"
echo "Default admin password is usually in: /opt/nexus/sonatype-work/nexus3/admin.password"
```
---

## Node Exporter [ Setup on Nexus Server ]

Docs: https://prometheus.io/docs/guides/node-exporter/

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin node_exporter

wget -O node_exporter.tar.gz "https://github.com/prometheus/node_exporter/releases/download/v1.9.1/node_exporter-1.9.1.linux-amd64.tar.gz"
tar -xvf node_exporter.tar.gz
sudo mv node_exporter-*/node_exporter /usr/local/bin/
rm -rf node_exporter*
```
**Systemd service:** (`/etc/systemd/system/node_exporter.service`)
```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
ExecStart=/usr/local/bin/node_exporter --collector.logind

[Install]
WantedBy=multi-user.target
```
Enable & start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
sudo systemctl start node_exporter
sudo systemctl status node_exporter
```
---

## Jenkins Plugins to Install

- Eclipse Temurin installer Plugin
- Email Extension Plugin
- OWASP Dependency-Check Plugin
- Pipeline: Stage View Plugin
- SonarQube Scanner for Jenkins
- Prometheus metrics plugin
- Nodejs
- Nexus Artifact Uploader
- Pipeline Maven Integration
- Pipeline Utility Steps
- Slack Notification
- Amazon Web Services SDK :: All
- Amazon ECR
- Pipeline: AWS Steps
- Docker Pipeline
- CloudBees Docker Build and Publish
- OWASP ZAP

---
## SonarQube Docker Container Run for Analysis

sonarqube:25.10.0.114319-community

```bash
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  -v sonarqube_logs:/opt/sonarqube/logs \
  -v sonarqube_extensions:/opt/sonarqube/extensions \
  sonarqube:25.9.0.112764-community
```
---

## Create the AWS Normal Account

- IAM account [jenkins]
- Policy [AmazonEC2ContainerRegistorFullaccess]
- Create the Security credentials.  [note it down one of the notepad]


## Create the Slack Account

- Create the Workspace
- Create the Channel
- Go to the Slack Markerplace [ Select the Jenkins CI ]
- Select the Channel Name
- Copy the Token
---

## Jenkins Credentials to Store

| Purpose       | ID            | Type          | Notes                               |
|---------------|---------------|---------------|-------------------------------------|
| Email         | mail-cred     | Username/app password |                             |
| SonarQube     | sonar-token   | Secret text   | From SonarQube application          |
| Docker Hub    | docker-cred   | Secret text   | From your Docker Hub profile        |
| Nexus         | nexuslogin    | Username/app password |                             |
| aws-cred      | awscreds      | Username/app password |     secret-key/access-key   |
| Slack         | slackcred   | Secret text   | From slack marketplace                |


Webhook example:  
`http://<jenkins-ip>:8080/sonarqube-webhook/`

---

## Jenkins Tools Configuration

- JDK [JDK17 , JDK21 ]
- SonarQube Scanner installations [sonar-scanner]
- Node  node16 
- Dependency-Check installations [dp-check]
- Maven [MAVEN3]

---

## Jenkins System Configuration

**SonarQube servers:**   
- Name: sonar-server  
- URL: http://sonar-ip-address:9000
- Credentials: Add from Jenkins credentials

**Extended E-mail Notification:**
- SMTP server: smtp.gmail.com
- SMTP Port: 465
- Use SSL
- Default user e-mail suffix: @gmail.com

**E-mail Notification:**
- SMTP server: smtp.gmail.com
- Default user e-mail suffix: @gmail.com
- Use SMTP Authentication: Yes
- User Name: example@gmail.com
- Password: Use credentials
- Use TLS: Yes
- SMTP Port: 587
- Reply-To Address: example@gmail.com


**Slack Notification:**
- workspace name
- channel name [devsecopscicd]
---
# Now See the configuration pipeline of the Jenkins


## update the nexus Details in the jenkins pipeline
- ip-address
- port
- artifact-repo-id [ vprofile-release ]
- go to the Nexus Server [ Settings --> Repositories --> create Repositories --> maven2 (hosted) --> vprofile-repo  --> create Repositories ]
---
## Create a Repository in the ECR

- vprofileappimg

## OWASP Link

Docs: https://www.zaproxy.org/download/

# Clean-up

- 2 EC2 instance
- ECR
- Delete the IAM jenkins User
- Delete the Slack Channel


## For more projects, check out  
[https://harishnshetty.github.io/projects.html](https://harishnshetty.github.io/projects.html)
## Explore New Videos By Click the Image
[![Video Tutorial](https://github.com/harishnshetty/image-data-project/blob/6135e01f68ebd6c691f8fc2304cfcb6d1e867dd6/ecr3.jpg)](https://www.youtube.com/@devopsHarishNShetty)

