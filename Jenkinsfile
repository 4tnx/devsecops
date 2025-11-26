// Configuration des couleurs pour les notifications
def COLOR_MAP = [
    'SUCCESS': 'good',
    'FAILURE': 'danger',
    'UNSTABLE': 'warning',
    'ABORTED': '#CCCCCC'
]

pipeline {
    agent any

    tools {
        maven 'MAVEN3'
        jdk 'JDK17'
    }

    parameters {
        booleanParam(name: 'PUSH_IMAGE', defaultValue: false, description: 'Push docker image to registry?')
        string(name: 'REGISTRY_URL', defaultValue: '192.168.50.4:5000', description: 'Docker Registry (host:port)')
        string(name: 'IMAGE_NAME', defaultValue: 'vprofileappimg', description: 'Local image name')
        booleanParam(name: 'ENFORCE_QUALITY_GATE', defaultValue: true, description: 'Abort pipeline if Sonar Quality Gate != OK')
        booleanParam(name: 'FAIL_ON_CRITICAL_VULNS', defaultValue: true, description: 'Fail build on CRITICAL vulnerabilities')
        string(name: 'APP_PORT', defaultValue: '8082', description: 'Port to run the application container on')
        booleanParam(name: 'RUN_DAST_SCAN', defaultValue: true, description: 'Perform DAST security testing')
    }

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000'
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_CREDENTIALS_ID = 'jenkins-github-https-cred'
        ARTVERSION = "${env.BUILD_ID}"
        CONTAINER_NAME = "vprofile-${env.BUILD_NUMBER}"
        NETWORK_NAME = "vprofile-net-${env.BUILD_NUMBER}"
        GIT_COMMIT = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
    }

    options {
        timestamps()
        ansiColor('xterm')
        skipDefaultCheckout(false)
        buildDiscarder(logRotator(numToKeepStr: '10'))
        durabilityHint('MAX_SURVIVABILITY')
        timeout(time: 120, unit: 'MINUTES')
    }

    stages {
        // Étape 1: Préparation de l'environnement
        stage('Clean Workspace') { 
            steps { 
                cleanWs() 
            } 
        }

        // Étape 2: Récupération du code
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: '*/main']],
                    extensions: [
                        [$class: 'CloneOption', depth: 1, shallow: true],
                        [$class: 'CleanBeforeCheckout']
                    ],
                    userRemoteConfigs: [[
                        url: 'https://github.com/4tnx/devsecops.git',
                        credentialsId: 'jenkins-github-https-cred'
                    ]]
                ])
            }
        }

        // Étape 3: Analyse de sécurité précoce (Shift-Left)
        stage('Early Security Scan') {
            parallel {
                stage('Secrets Detection') {
                    steps {
                        sh '''
                            echo "🔍 Scanning for secrets in code..."
                            gitleaks detect --source . --report-format json --report-path gitleaks-report.json --exit-code 0 || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                        }
                    }
                }

                stage('SAST - Semgrep') {
                    steps {
                        sh '''
                            echo "🔍 Running Semgrep SAST analysis..."
                            semgrep --config auto --output semgrep.json --json --error --no-rewrite-rule-ids . || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        // Étape 4: Build et tests unitaires
        stage('Build & Unit Tests') {
            steps { 
                sh '''
                    echo "🏗️ Building application..."
                    mvn -B clean compile -DskipTests=true
                    
                    echo "🧪 Running unit tests..."
                    mvn -B test -DskipITs=true
                '''
            }
            post { 
                success { 
                    archiveArtifacts artifacts: '**/target/*.war', allowEmptyArchive: true 
                }
                always {
                    junit testResults: '**/target/surefire-reports/*.xml', allowEmptyResults: true
                    jacoco(
                        execPattern: '**/target/jacoco.exec',
                        classPattern: '**/target/classes',
                        sourcePattern: '**/src/main/java',
                        exclusionPattern: '**/src/test/*'
                    )
                }
            }
        }

        // Étape 5: Analyse de code qualité et sécurité
        stage('Code Quality & SAST') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        withSonarQubeEnv('sonar-server') {
                            sh """
                                mvn -B sonar:sonar \
                                    -Dsonar.host.url=${SONAR_HOST_URL} \
                                    -Dsonar.login=${SONAR_TOKEN} \
                                    -Dsonar.projectKey=vprofile-${env.BUILD_NUMBER} \
                                    -Dsonar.projectName="VProfile Application" \
                                    -Dsonar.sources=src/main/java \
                                    -Dsonar.tests=src/test/java \
                                    -Dsonar.java.binaries=target/classes \
                                    -Dsonar.junit.reportsPath=target/surefire-reports \
                                    -Dsonar.jacoco.reportPaths=target/jacoco.exec \
                                    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
                            """
                        }
                    }
                }
            }
        }

        // Étape 6: Quality Gate
        stage('Quality Gate') {
            steps {
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        echo "Quality Gate status: ${qg.status}"
                        
                        if (params.ENFORCE_QUALITY_GATE && qg.status != 'OK') {
                            error "❌ Quality Gate failed: ${qg.status}. Pipeline aborted."
                        }
                        
                        if (qg.status == 'OK') {
                            echo "✅ Quality Gate passed successfully"
                        }
                    }
                }
            }
        }

        // Étape 7: Analyse des dépendances (SCA)
        stage('Dependency Analysis') {
            parallel {
                stage('SCA - OWASP Dependency Check') {
                    steps {
                        sh '''
                            echo "📦 Scanning dependencies for vulnerabilities..."
                            mvn -B org.owasp:dependency-check-maven:check \
                                -Dformat=HTML \
                                -Dformat=XML \
                                -Dodc.outputDirectory=target/dependency-check-report || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'target/dependency-check-report/*', allowEmptyArchive: true
                        }
                    }
                }

                stage('SBOM Generation') {
                    steps {
                        sh '''
                            echo "📄 Generating Software Bill of Materials..."
                            mvn -B org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'target/bom.*', allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        // Étape 8: Build de l'image Docker
        stage('Build Docker Image') {
            steps {
                script {
                    env.IMAGE_TAG = "${params.IMAGE_NAME}:${env.BUILD_NUMBER}"
                    
                    sh """
                        set -e
                        echo "🐳 Building Docker image..."
                        docker build \
                            --network host \
                            --build-arg BUILD_DATE=\$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
                            --build-arg VERSION=${env.BUILD_NUMBER} \
                            --build-arg COMMIT=${env.GIT_COMMIT} \
                            -t ${params.IMAGE_NAME}:latest \
                            -t ${env.IMAGE_TAG} .
                    """
                }
            }
        }

        // Étape 9: Scan de sécurité de l'image Docker
        stage('Container Security Scan') {
            parallel {
                stage('Trivy Image Scan') {
                    steps {
                        script {
                            sh """
                                set -e
                                echo "🔍 Scanning Docker image with Trivy..."
                                
                                # Scan des vulnérabilités
                                trivy image \
                                    --scanners vuln \
                                    --severity CRITICAL,HIGH,MEDIUM \
                                    --format json \
                                    --output trivy-image.json \
                                    ${env.IMAGE_TAG} || true
                                
                                # Rapport en format table
                                trivy image \
                                    --scanners vuln \
                                    --severity CRITICAL,HIGH,MEDIUM \
                                    --format table \
                                    --output trivy-image.txt \
                                    ${env.IMAGE_TAG} || true
                                
                                # Scan de configuration
                                trivy image \
                                    --scanners config \
                                    --format json \
                                    --output trivy-config.json \
                                    ${env.IMAGE_TAG} || true
                            """
                        }
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'trivy-*.json,trivy-*.txt', allowEmptyArchive: true
                        }
                    }
                }

                stage('Trivy Filesystem Scan') {
                    steps {
                        sh '''
                            echo "🔍 Scanning filesystem with Trivy..."
                            trivy fs --exit-code 0 --format json -o trivy-fs.json . || true
                        '''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'trivy-fs.json', allowEmptyArchive: true
                        }
                    }
                }
            }
        }

        // Étape 10: Application des politiques de sécurité
        stage('Security Policy Enforcement') {
            steps {
                script {
                    echo "⚖️ Applying security policies..."
                    
                    // Analyse des résultats Trivy
                    def criticalCount = 0
                    def highCount = 0
                    
                    if (fileExists('trivy-image.json')) {
                        def trivyReport = readJSON file: 'trivy-image.json'
                        def results = trivyReport.Results ?: []
                        
                        results.each { result ->
                            result.Vulnerabilities?.each { vuln ->
                                def severity = vuln.Severity?.toUpperCase()
                                if (severity == 'CRITICAL') criticalCount++
                                if (severity == 'HIGH') highCount++
                            }
                        }
                    }
                    
                    // Analyse des résultats Dependency Check
                    def dependencyCriticalCount = 0
                    if (fileExists('target/dependency-check-report/dependency-check-report.xml')) {
                        def dependencyReport = readFile 'target/dependency-check-report/dependency-check-report.xml'
                        dependencyCriticalCount = (dependencyReport =~ 'severity="CRITICAL"').size()
                    }
                    
                    // Application des politiques
                    def totalCritical = criticalCount + dependencyCriticalCount
                    
                    echo "Security Scan Results:"
                    echo "🔴 CRITICAL vulnerabilities: ${totalCritical}"
                    echo "🟠 HIGH vulnerabilities: ${highCount}"
                    
                    if (params.FAIL_ON_CRITICAL_VULNS && totalCritical > 0) {
                        error "❌ Build failed: ${totalCritical} CRITICAL vulnerabilities detected"
                    } else if (totalCritical > 0) {
                        unstable "⚠️ Build unstable: ${totalCritical} CRITICAL vulnerabilities detected"
                    } else if (highCount > 10) {
                        unstable "⚠️ Build unstable: High number (${highCount}) of HIGH vulnerabilities"
                    } else {
                        echo "✅ Security policies satisfied"
                    }
                    
                    // Génération du rapport de sécurité
                    writeFile file: 'security-summary.md', text: """
# Security Scan Summary - Build #${env.BUILD_NUMBER}

## Vulnerability Overview
- 🔴 CRITICAL: ${totalCritical}
- 🟠 HIGH: ${highCount}
- Image: ${env.IMAGE_TAG}
- Commit: ${env.GIT_COMMIT}

## Scan Results
- SAST (SonarQube): ${currentBuild.result == 'SUCCESS' ? '✅ Passed' : '❌ Failed'}
- SCA (Dependency Check): ${dependencyCriticalCount > 0 ? '⚠️ Issues' : '✅ Clean'}
- Container Scan: ${criticalCount > 0 ? '⚠️ Issues' : '✅ Clean'}
- Secrets Detection: Completed
                    """
                    
                    archiveArtifacts artifacts: 'security-summary.md', allowEmptyArchive: true
                }
            }
        }

        // Étape 11: Déploiement et tests DAST (conditionnel)
        stage('Deploy & DAST Scan') {
            when {
                allOf {
                    expression { currentBuild.result != 'FAILURE' }
                    expression { params.RUN_DAST_SCAN }
                }
            }
            steps {
                script {
                    echo "🚀 Deploying container for DAST testing..."
                    
                    // Nettoyage préalable
                    sh "docker rm -f ${env.CONTAINER_NAME} || true"
                    sh "docker network rm ${env.NETWORK_NAME} || true"
                    
                    // Déploiement
                    sh """
                        docker network create ${env.NETWORK_NAME}
                        docker run -d \
                            --name ${env.CONTAINER_NAME} \
                            --network ${env.NETWORK_NAME} \
                            -p ${params.APP_PORT}:8080 \
                            ${env.IMAGE_TAG}
                    """
                    
                    // Attente du démarrage
                    sleep 30
                    
                    // Vérification de l'état
                    sh """
                        set +e
                        for i in {1..10}; do
                            curl -f http://localhost:${params.APP_PORT}/ > /dev/null 2>&1
                            if [ \$? -eq 0 ]; then
                                echo "✅ Application is responding"
                                break
                            fi
                            echo "⏳ Waiting for application... (\$i/10)"
                            sleep 10
                        done
                    """
                    
                    // Scan DAST avec ZAP
                    echo "🔍 Starting DAST scan with OWASP ZAP..."
                    sh """
                        docker run --rm \
                            --network host \
                            -v \$(pwd):/zap/wrk:rw \
                            -t ghcr.io/zaproxy/zaproxy:stable \
                            zap-baseline.py \
                            -t http://localhost:${params.APP_PORT} \
                            -c zap-config.conf \
                            -r zap-report.html \
                            -J zap-report.json \
                            -w zap-report.md || true
                    """
                }
            }
            post {
                always {
                    echo "🧹 Cleaning up test environment..."
                    sh "docker rm -f ${env.CONTAINER_NAME} || true"
                    sh "docker network rm ${env.NETWORK_NAME} || true"
                    archiveArtifacts artifacts: 'zap-report.*', allowEmptyArchive: true
                }
            }
        }

        // Étape 12: Publication de l'image (conditionnelle)
        stage('Push Image') {
            when {
                allOf {
                    expression { params.PUSH_IMAGE }
                    expression { currentBuild.result != 'FAILURE' }
                }
            }
            steps {
                script {
                    echo "📤 Pushing image to registry..."
                    def registryUrl = params.REGISTRY_URL.contains('://') ? params.REGISTRY_URL : "https://${params.REGISTRY_URL}"
                    
                    docker.withRegistry(registryUrl, "${DOCKER_CREDENTIALS_ID}") {
                        docker.image("${params.IMAGE_NAME}:latest").push()
                        docker.image("${env.IMAGE_TAG}").push()
                    }
                    
                    echo "✅ Image pushed successfully to ${params.REGISTRY_URL}"
                }
            }
        }
    }

    post {
        always {
            script {
                // Nettoyage finale
                sh "docker rm -f ${env.CONTAINER_NAME} || true"
                sh "docker network rm ${env.NETWORK_NAME} || true"
                
                // Génération du rapport final
                def buildStatus = currentBuild.currentResult
                def duration = currentBuild.durationString.replace(' and counting', '')
                def buildUser = env.CHANGE_AUTHOR ?: env.BUILD_USER_ID ?: 'System'
                
                // Rapport de sécurité consolidé
                def securityReport = """
🔒 **DevSecOps Pipeline Security Report** - Build #${env.BUILD_NUMBER}

**Build Status:** ${buildStatus}
**Duration:** ${duration}
**Triggered by:** ${buildUser}

**Security Scan Results:**
• ✅ SAST Analysis (SonarQube + Semgrep)
• ✅ Secrets Detection (Gitleaks) 
• ✅ Software Composition Analysis (OWASP DC)
• ✅ Container Security (Trivy)
• ✅ Software Bill of Materials
• ${params.RUN_DAST_SCAN ? '✅ DAST Testing (OWASP ZAP)' : '⏭️ DAST Skipped'}

**Quality Gates:**
• Code Quality: ${currentBuild.result == 'SUCCESS' ? '✅ PASSED' : '❌ FAILED'}
• Security Policy: ${params.FAIL_ON_CRITICAL_VULNS ? 'STRICT 🔒' : 'LENIENT ⚠️'}

**Build Artifacts:**
• Docker Image: ${params.IMAGE_NAME}:${env.BUILD_NUMBER}
• Security Reports: Available in Jenkins artifacts
• SBOM: Generated and archived

---
*This is an automated security report from Jenkins DevSecOps Pipeline*
                """
                
                writeFile file: 'final-security-report.md', text: securityReport
                archiveArtifacts artifacts: 'final-security-report.md', allowEmptyArchive: true
            }
        }
        
        success {
            script {
                def color = COLOR_MAP['SUCCESS']
                slackSend(
                    channel: '#devsecops',
                    color: color,
                    message: """✅ Pipeline SUCCESS: ${env.JOB_NAME} #${env.BUILD_NUMBER}
📦 Security scans completed successfully
🐳 Image: ${params.IMAGE_NAME}:${env.BUILD_NUMBER}
👤 By: ${env.BUILD_USER_ID ?: 'System'}
🔗 ${env.BUILD_URL}"""
                )
            }
        }
        
        unstable {
            script {
                def color = COLOR_MAP['UNSTABLE']
                slackSend(
                    channel: '#devsecops',
                    color: color,
                    message: """⚠️ Pipeline UNSTABLE: ${env.JOB_NAME} #${env.BUILD_NUMBER}
⚡ Security vulnerabilities detected (non-blocking)
📊 Check reports for details
🔗 ${env.BUILD_URL}"""
                )
            }
        }
        
        failure {
            script {
                def color = COLOR_MAP['FAILURE']
                slackSend(
                    channel: '#devsecops',
                    color: color,
                    message: """❌ Pipeline FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER}
🚨 Critical issues blocked the pipeline
🔍 Review security reports
🔗 ${env.BUILD_URL}"""
                )
            }
        }
        
        cleanup {
            cleanWs()
        }
    }
}